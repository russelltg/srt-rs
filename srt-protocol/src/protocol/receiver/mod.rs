use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use log::{debug, info, trace};

use arq::AutomaticRepeatRequestAlgorithm;
use buffer::RecvBuffer;

use crate::connection::ConnectionStatus;
use crate::packet::{ControlPacket, ControlTypes, DataPacket, FullAckSeqNumber, Packet};
use crate::protocol::encryption::Cipher;
use crate::protocol::handshake::Handshake;
use crate::protocol::receiver::time::ReceiveTimers;
use crate::protocol::{TimeBase, TimeStamp};
use crate::ConnectionSettings;

use super::TimeSpan;
use log::error;

mod arq;
mod buffer;
mod time;

#[derive(Debug)]
pub struct Receiver {
    settings: ConnectionSettings,

    handshake: Handshake,

    time_base: TimeBase,

    timers: ReceiveTimers,

    receive_buffer: RecvBuffer,

    arq: AutomaticRepeatRequestAlgorithm,

    cipher: Cipher,

    control_packets: VecDeque<Packet>,

    data_release: VecDeque<(Instant, Bytes)>,

    status: ConnectionStatus,
}

impl Receiver {
    pub fn new(settings: ConnectionSettings, handshake: Handshake) -> Self {
        info!(
            "Receiving started from {:?}, with latency={:?}",
            settings.remote, settings.recv_tsbpd_latency
        );

        Receiver {
            settings: settings.clone(),
            timers: ReceiveTimers::new(settings.socket_start_time),
            time_base: TimeBase::new(settings.socket_start_time),
            control_packets: VecDeque::new(),
            data_release: VecDeque::new(),
            handshake,
            receive_buffer: RecvBuffer::with(&settings),
            cipher: Cipher::new(settings.crypto_manager),
            arq: AutomaticRepeatRequestAlgorithm::new(settings.init_seq_num),
            status: ConnectionStatus::Open(settings.recv_tsbpd_latency),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.status.is_closed()
    }

    pub fn is_flushed(&self) -> bool {
        debug!(
            "{:?}|{:?}|recv - {:?}:{},{}",
            TimeSpan::from_interval(self.settings.socket_start_time, Instant::now()),
            self.settings.local_sockid,
            self.receive_buffer.next_msg_ready(),
            self.arq.lr_ack_acked,
            self.receive_buffer.next_release()
        );

        self.receive_buffer.next_msg_ready().is_none()
            && self.arq.lr_ack_acked == self.receive_buffer.next_release() // packets have been acked and all acks have been acked (ack2)
            && self.control_packets.is_empty()
            && self.data_release.is_empty()
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
            self.arq.lr_ack_acked = self.receive_buffer.next_release()
        }
    }

    pub fn reset_exp(&mut self, now: Instant) {
        self.timers.reset_exp(now);
    }

    pub fn synchronize_clock(&mut self, now: Instant, ts: TimeStamp) {
        self.receive_buffer.synchronize_clock(now, ts)
    }

    pub fn handle_data_packet(&mut self, now: Instant, data: DataPacket) {
        // we've already gotten this packet, drop it
        if self.receive_buffer.next_release() > data.seq_number {
            debug!("Received packet {:?} twice", data.seq_number);
            return;
        }

        let (nak, ack) = self
            .arq
            .handle_data_packet(now, data.seq_number, data.payload.len());

        if let Some(loss_list) = nak {
            self.send_control(now, ControlTypes::Nak(loss_list));
        }
        if let Some(light_ack) = ack {
            self.send_control(now, ControlTypes::Ack(light_ack));
        }

        match self.cipher.decrypt(data) {
            Ok(data) => self.receive_buffer.add(data),
            Err(e) => error!("{:?} {:?}", self.settings.local_sockid, e),
        }
    }

    pub fn handle_ack2_packet(&mut self, seq_num: FullAckSeqNumber, ack2_arrival_time: Instant) {
        self.arq.handle_ack2_packet(ack2_arrival_time, seq_num);

        // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
        self.timers.update_rtt(self.arq.rtt());
    }

    pub fn rekey(
        &mut self,
        key_message: &crate::packet::control::SrtKeyMessage,
    ) -> Result<(), crate::pending_connection::ConnectionReject> {
        match self.settings.crypto_manager {
            None => {
                error!(
                    "Unexpcted re-key message on unencrypted connection {:?}",
                    key_message
                );
                Ok(())
            }
            Some(ref mut crypto_manager) => crypto_manager.rekey(key_message),
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
        // try to release packets
        while let Some(d) = self.receive_buffer.next_msg_tsbpd(now) {
            self.data_release.push_back(d);
        }

        // drop packets
        // TODO: do something with this
        let _dropped = self.receive_buffer.drop_too_late_packets(now);

        self.data_release.pop_front()
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        self.control_packets
            .pop_front()
            .map(|packet| (packet, self.settings.remote))
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        let next_message = self.receive_buffer.next_message_release_time();
        let unacked_packets = self.receive_buffer.unacked_packet_count();
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
