use std::{collections::VecDeque, net::SocketAddr, time::Instant};

use bytes::Bytes;
use log::{debug, error, info, trace, warn};

use crate::{
    connection::ConnectionStatus,
    packet::{ControlPacket, ControlTypes, DataPacket, FullAckSeqNumber, Packet},
    protocol::{
        encryption::Cipher,
        receiver::{arq::AutomaticRepeatRequestAlgorithm, time::ReceiveTimers},
        TimeBase, TimeStamp,
    },
    ConnectionSettings, SeqNumber,
};

mod arq;
mod buffer;
mod history;
mod time;

#[derive(Debug)]
pub struct Receiver {
    settings: ConnectionSettings,

    time_base: TimeBase,

    timers: ReceiveTimers,

    arq: AutomaticRepeatRequestAlgorithm,

    cipher: Cipher,

    control_packets: VecDeque<Packet>,

    status: ConnectionStatus,
}

impl Receiver {
    pub fn new(settings: ConnectionSettings) -> Self {
        info!(
            "Receiving started from {:?}, with latency={:?}",
            settings.remote, settings.recv_tsbpd_latency
        );

        Receiver {
            settings: settings.clone(),
            time_base: TimeBase::new(settings.socket_start_time),
            cipher: Cipher::new(settings.crypto_manager),
            arq: AutomaticRepeatRequestAlgorithm::new(
                settings.socket_start_time,
                settings.recv_tsbpd_latency,
                settings.init_seq_num,
            ),
            timers: ReceiveTimers::new(settings.socket_start_time),
            control_packets: VecDeque::new(),
            status: ConnectionStatus::Open(settings.recv_tsbpd_latency),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.status.is_closed()
    }

    pub fn is_flushed(&self) -> bool {
        self.arq.is_flushed() // packets have been acked and all acks have been acked (ack2)
            && self.control_packets.is_empty()
    }

    pub fn check_timers(&mut self, now: Instant) {
        //   Data Sending Algorithm:
        //   1) Query the system time to check if ACK, NAK, or EXP timer has
        //      expired. If there is any, process the event (as described below
        //      in this section) and reset the associated time variables. For
        //      ACK, also check the ACK packet interval.
        if self.timers.check_full_ack(now).is_some() {
            self.on_full_ack_event(now);
        }
        if self.timers.check_nak(now).is_some() {
            self.on_nak_event(now);
        }
        if self.timers.check_peer_idle_timeout(now).is_some() {
            self.on_peer_idle_timeout(now);
        }
        if self.status.check_close_timeout(now, self.is_flushed()) {
            debug!("{:?} receiver close timed out", self.settings.local_sockid);
            // receiver is closing, there is no need to track ACKs anymore
            self.arq.clear();
        }
    }

    pub fn reset_exp(&mut self, now: Instant) {
        self.timers.reset_exp(now);
    }

    pub fn synchronize_clock(&mut self, now: Instant, ts: TimeStamp) {
        self.arq.synchronize_clock(now, ts)
    }

    pub fn handle_data_packet(&mut self, now: Instant, data: DataPacket) {
        match self.cipher.decrypt(data) {
            Ok(data) => match self.arq.handle_data_packet(now, data) {
                Ok((nak, ack)) => {
                    if let Some(loss_list) = nak {
                        self.send_control(now, ControlTypes::Nak(loss_list));
                    }
                    if let Some(light_ack) = ack {
                        self.send_control(now, ControlTypes::Ack(light_ack));
                    }
                }
                Err(e) => error!(
                    "invalid data packet: {:?} {:?}",
                    self.settings.local_sockid, e
                ),
            },
            Err(e) => error!(
                "decryption failed: {:?} {:?}",
                self.settings.local_sockid, e
            ),
        }
    }

    pub fn handle_ack2_packet(&mut self, seq_num: FullAckSeqNumber, ack2_arrival_time: Instant) {
        // 1) Locate the related ACK in the ACK History Window according to the
        //    ACK sequence number in this ACK2.
        // 2) Update the largest ACK number ever been acknowledged.
        if let Some(rtt) = self.arq.handle_ack2_packet(ack2_arrival_time, seq_num) {
            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
            self.timers.update_rtt(rtt);
        } else {
            warn!(
                "ACK sequence number in ACK2 packet not found in ACK history: {:?}",
                seq_num
            );
        }
    }

    pub fn handle_drop_request(&mut self, now: Instant, first: SeqNumber, last: SeqNumber) {
        if let Some((begin, end, count)) = self.arq.handle_drop_request(now, first, last) {
            info!(
                "Dropped {} packets in the range of [{:?}, {:?})",
                count, begin, end
            );
        }
    }

    pub fn handle_shutdown_packet(&mut self, now: Instant) {
        info!(
            "{:?}: Shutdown packet received, flushing receiver...",
            self.settings.local_sockid
        );
        self.status.drain(now);
    }

    pub fn next_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        self.arq.pop_next_message(now)
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        self.control_packets
            .pop_front()
            .map(|packet| (packet, self.settings.remote))
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        let next_message = self.arq.next_message_release_time();
        let unacked_packets = self.arq.unacked_packet_count();
        self.timers.next_timer(now, next_message, unacked_packets)
    }

    fn on_full_ack_event(&mut self, now: Instant) {
        if let Some(ack) = self.arq.on_full_ack_event(now) {
            trace!("Ack event hit {:?}", self.settings.local_sockid);

            // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
            // receiver buffer size).
            self.send_control(now, ControlTypes::Ack(ack));
        }
    }

    fn on_nak_event(&mut self, now: Instant) {
        if let Some(loss_list) = self.arq.on_nak_event(now) {
            self.send_control(now, ControlTypes::Nak(loss_list));
        }
    }

    fn on_peer_idle_timeout(&mut self, now: Instant) {
        self.status.drain(now);
        self.send_control(now, ControlTypes::Shutdown);
    }

    fn send_control(&mut self, now: Instant, control: ControlTypes) {
        if self.status.is_open() {
            self.control_packets
                .push_back(Packet::Control(ControlPacket {
                    timestamp: self.time_base.timestamp_from(now),
                    dest_sockid: self.settings.remote_sockid,
                    control_type: control,
                }));
        }
    }
}
