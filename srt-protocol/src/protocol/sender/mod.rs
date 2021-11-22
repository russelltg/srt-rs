mod buffer;
mod congestion_control;
mod encapsulate;

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::{
    connection::{ConnectionSettings, ConnectionStatus},
    packet::*,
    protocol::{
        encryption::Cipher,
        output::Output,
        time::{TimeBase, Timers},
    },
    statistics::SocketStatistics,
};

use buffer::{AckAction, Loss, SendBuffer, SenderAction};
use congestion_control::SenderCongestionControl;
use encapsulate::Encapsulate;

#[derive(Debug)]
pub struct Sender {
    time_base: TimeBase,
    encapsulate: Encapsulate,
    encrypt: Cipher,
    send_buffer: SendBuffer,
    congestion_control: SenderCongestionControl,
}

impl Sender {
    pub fn new(settings: ConnectionSettings) -> Self {
        Self {
            time_base: TimeBase::new(settings.socket_start_time),
            encapsulate: Encapsulate::new(&settings),
            encrypt: Cipher::new(settings.crypto_manager.clone()),
            send_buffer: SendBuffer::new(&settings),
            congestion_control: SenderCongestionControl::new(settings.bandwidth.clone()),
        }
    }

    pub fn is_flushed(&self) -> bool {
        self.send_buffer.is_flushed()
    }

    pub fn has_packets_to_send(&self) -> bool {
        self.send_buffer.has_packets_to_send()
    }

    pub fn tx_buffer_time(&self) -> Duration {
        self.send_buffer.duration()
    }
}

pub struct SenderContext<'a> {
    status: &'a mut ConnectionStatus,
    timers: &'a mut Timers,
    output: &'a mut Output,
    statistics: &'a mut SocketStatistics,
    sender: &'a mut Sender,
}

impl<'a> SenderContext<'a> {
    pub fn new(
        status: &'a mut ConnectionStatus,
        timers: &'a mut Timers,
        output: &'a mut Output,
        statistics: &'a mut SocketStatistics,
        sender: &'a mut Sender,
    ) -> Self {
        Self {
            status,
            timers,
            output,
            statistics,
            sender,
        }
    }

    pub fn handle_data(&mut self, now: Instant, item: (Instant, Bytes)) {
        let (time, data) = item;
        let ts = self.sender.time_base.timestamp_from(time);
        let encapsulate = &mut self.sender.encapsulate;
        let buffer = &mut self.sender.send_buffer;
        let encrypt = &mut self.sender.encrypt;
        let (packets, bytes) = encapsulate.encapsulate(ts, data, |packet| {
            let (packet, _) = encrypt.encrypt(packet);
            buffer.push_data(packet);
        });
        let snd_period = self.sender.congestion_control.on_input(now, packets, bytes);
        if let Some(snd_period) = snd_period {
            self.timers.update_snd_period(snd_period)
        }
    }

    pub fn handle_ack_packet(&mut self, now: Instant, ack: Acknowledgement) {
        self.statistics.rx_ack += 1;
        if matches!(ack, Acknowledgement::Lite(_)) {
            self.statistics.rx_light_ack += 1;
        }

        match self
            .sender
            .send_buffer
            .update_largest_acked_seq_number(ack.ack_number(), ack.full_ack_seq_number())
        {
            Ok(AckAction {
                received: _,
                recovered: _,
                send_ack2,
            }) => {
                // TODO: add received and recovered to connection statistics
                if let Some(_stats) = ack.statistics() {
                    // TODO: add these to connection statistics
                }
                if let Some(full_ack) = send_ack2 {
                    self.output.send_control(now, ControlTypes::Ack2(full_ack))
                }
            }
            Err(_error) => {
                // self.warn("ack", now, &error);
                // TODO: add statistic
                // self.statistics.rx_ack2_errors += 1;
            }
        }
    }

    pub fn handle_nak_packet(&mut self, now: Instant, nak: CompressedLossList) {
        self.statistics.rx_nak += 1;
        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
        for (loss, range) in self.sender.send_buffer.add_to_loss_list(nak) {
            //self.debug("nak", now, &(&loss, &range));
            // TODO: figure out better statistics
            use Loss::*;
            match loss {
                Ignored => {
                    self.statistics.tx_loss_data += 1;
                }
                Added => {
                    self.statistics.tx_loss_data += 1;
                }
                Dropped => {
                    self.statistics.tx_dropped_data += 1;

                    // On a Live stream, where each packet is a message, just one NAK with
                    // a compressed packet loss interval of significant size (e.g. [1,
                    // 100_000] will result in a deluge of message drop request packet
                    // transmissions from the sender, resembling a DoS attack on the receiver.
                    // Even more pathological, this is most likely to happen when we absolutely
                    // do not want it to happen, such as during periods of decreased network
                    // throughput.
                    //
                    // For this reason, this implementation is explicitly inconsistent with the
                    // reference implementation, which only sends a single message per message
                    // drop request, if the message is still in the send buffer. We always send
                    self.output.send_control(
                        now,
                        ControlTypes::new_drop_request(MsgNumber::new_truncate(0), range),
                    )
                }
            }
        }
    }

    pub fn on_snd_event(&mut self, now: Instant, elapsed_periods: u32) {
        use SenderAction::*;
        let ts_now = self.sender.time_base.timestamp_from(now);
        let actions = self.sender.send_buffer.next_snd_actions(
            ts_now,
            elapsed_periods,
            self.status.should_drain_send_buffer(),
        );
        for action in actions {
            match action {
                Send(d) => {
                    self.output.send_data(now, d);
                }
                Retransmit(d) => {
                    self.statistics.tx_retransmit_data += 1;
                    self.output.send_data(now, d);
                }
                Drop(_) => {}
                WaitForInput => {
                    break;
                }
                WaitForAck { .. } => {
                    break;
                }
            }
        }
    }
}
