mod arq;
mod buffer;
mod history;
mod time;

use std::{ops::RangeInclusive, time::Instant};

use arq::AutomaticRepeatRequestAlgorithm;

use crate::{
    connection::ConnectionSettings,
    packet::*,
    protocol::{
        encryption::{Cipher, DecryptionError},
        output::Output,
        time::Timers,
    },
    statistics::SocketStatistics,
};

#[derive(Debug, Eq, PartialEq)]
pub enum DataPacketError {
    // "Dropping packet {}, receive buffer full"
    BufferFull {
        seq_number: SeqNumber,
        buffer_size: usize,
    },
    // "Packet received too far in the future for configured receive buffer size. Discarding packet (buffer would need to be {} packets larger)"
    PacketTooEarly {
        seq_number: SeqNumber,
        buffer_available: usize,
        buffer_required: usize,
    },
    // "Too-late packet {} was received, discarding"
    PacketTooLate {
        seq_number: SeqNumber,
        seq_number_0: SeqNumber,
    },
    // "Duplicate packet {}"
    DiscardedDuplicate {
        seq_number: SeqNumber,
    },
    DecryptionError(DecryptionError),
}

#[derive(Debug, Eq, PartialEq)]
pub enum DataPacketAction {
    Received {
        lrsn: SeqNumber,
        recovered: bool,
    },
    ReceivedWithLoss(CompressedLossList),
    ReceivedWithLightAck {
        light_ack: SeqNumber,
        recovered: bool,
    },
}

#[derive(Debug)]
pub struct Receiver {
    pub arq: AutomaticRepeatRequestAlgorithm,
    pub cipher: Cipher,
}

impl Receiver {
    pub fn is_flushed(&self) -> bool {
        self.arq.is_flushed()
    }
}

impl Receiver {
    pub fn new(settings: ConnectionSettings) -> Self {
        Receiver {
            cipher: Cipher::new(settings.crypto_manager),
            arq: AutomaticRepeatRequestAlgorithm::new(
                settings.socket_start_time,
                settings.recv_tsbpd_latency,
                settings.init_seq_num,
                settings.recv_buffer_size,
            ),
        }
    }
}

pub struct ReceiverContext<'a> {
    timers: &'a mut Timers,
    output: &'a mut Output,
    statistics: &'a mut SocketStatistics,
    receiver: &'a mut Receiver,
}

impl<'a> ReceiverContext<'a> {
    pub fn new(
        timers: &'a mut Timers,
        output: &'a mut Output,
        statistics: &'a mut SocketStatistics,
        receiver: &'a mut Receiver,
    ) -> Self {
        Self {
            timers,
            statistics,
            output,
            receiver,
        }
    }

    pub fn synchronize_clock(&mut self, now: Instant, ts: TimeStamp) {
        if let Some(_adjustment) = self.receiver.arq.synchronize_clock(now, ts) {
            //self.debug("clock sync", now, &adjustment);
            self.statistics.rx_clock_adjustments += 1;
        }
    }

    pub fn handle_data_packet(&mut self, now: Instant, data: DataPacket) {
        use Acknowledgement::*;
        use ControlTypes::*;
        self.statistics.rx_data += 1;
        let bytes = data.payload.len() as u64;
        let data = self
            .receiver
            .cipher
            .decrypt(data)
            .map_err(DataPacketError::DecryptionError)
            .and_then(|data| self.receiver.arq.handle_data_packet(now, data));

        match data {
            Ok(action) => {
                self.statistics.rx_unique_data += 1;
                self.statistics.rx_unique_bytes += bytes;

                use DataPacketAction::*;
                match action {
                    Received { recovered, .. } => {
                        if recovered {
                            self.statistics.rx_retransmit_data += 1;
                        }
                    }
                    ReceivedWithLoss(loss_list) => {
                        self.output.send_control(now, Nak(loss_list));
                    }
                    ReceivedWithLightAck {
                        light_ack,
                        recovered,
                    } => {
                        if recovered {
                            self.statistics.rx_retransmit_data += 1;
                        }
                        self.output.send_control(now, Ack(Lite(light_ack)));
                    }
                }
            }
            Err(e) => {
                use DataPacketError::*;
                match e {
                    BufferFull { .. } | PacketTooEarly { .. } | PacketTooLate { .. } => {
                        self.statistics.rx_dropped_data += 1;
                        self.statistics.rx_dropped_bytes += bytes;
                    }
                    DecryptionError(_) => {
                        self.statistics.rx_decrypt_errors += 1;
                        self.statistics.rx_decrypt_error_bytes += bytes;
                    }
                    DiscardedDuplicate { .. } => {}
                }
            }
        }
    }

    pub fn handle_ack2_packet(&mut self, now: Instant, seq_num: FullAckSeqNumber) {
        self.statistics.rx_ack2 += 1;
        let rtt = self.receiver.arq.handle_ack2_packet(now, seq_num);
        if let Some(rtt) = rtt {
            self.timers.update_rtt(rtt);
            //self.warn("ack not found", now, &seq_num);
            self.statistics.rx_ack2_errors += 1;
        }
    }

    pub fn handle_drop_request(&mut self, now: Instant, drop: RangeInclusive<SeqNumber>) {
        let range = *drop.start()..*drop.end() + 1;
        let dropped = self.receiver.arq.handle_drop_request(now, range) as u64;
        if dropped > 0 {
            //self.warn("packets dropped", now, &(dropped, drop));
            self.statistics.rx_dropped_data += dropped;
        }
    }

    pub fn on_full_ack_event(&mut self, now: Instant) {
        if let Some(ack) = self.receiver.arq.on_full_ack_event(now) {
            // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
            // receiver buffer size).
            self.output.send_control(now, ControlTypes::Ack(ack));
        }
    }

    pub fn on_nak_event(&mut self, now: Instant) {
        if let Some(loss_list) = self.receiver.arq.on_nak_event(now) {
            self.output.send_control(now, ControlTypes::Nak(loss_list));
        }
    }

    pub fn on_close_timeout(&mut self, _now: Instant) {
        //self.debug("timed out", now, &self.receiver.arq);
        self.receiver.arq.clear()
    }
}
