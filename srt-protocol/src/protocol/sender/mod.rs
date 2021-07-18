mod buffer;
mod congestion_control;
mod encapsulate;
mod encrypt;
mod output;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::debug;

use super::TimeSpan;
use crate::packet::{AckControlInfo, ControlTypes, HandshakeControlInfo};
use crate::packet::{CompressedLossList, FullAckSeqNumber};
use crate::protocol::handshake::Handshake;
use crate::protocol::Timer;
use crate::{ConnectionSettings, DataPacket, Packet};

use crate::connection::ConnectionStatus;
use crate::packet::ControlTypes::DropRequest;
use crate::protocol::sender::output::Output;
use buffer::SendBuffer;
use congestion_control::{LiveDataRate, SenderCongestionControl};
use std::cmp::{max, min};

#[derive(Debug)]
pub enum SenderError {}

pub type SenderResult = Result<(), SenderError>;

#[derive(Debug, Clone, Copy)]
pub struct SenderMetrics {
    /// Round trip time, in microseconds
    pub rtt: TimeSpan,

    /// Round trip time variance
    pub rtt_var: TimeSpan,

    /// packet arrival rate
    pub pkt_arr_rate: u32,

    /// estimated link capacity
    pub est_link_cap: u32,

    /// Total lost packets
    pub lost_packets: u32,

    /// Total retransmitted packets
    pub retrans_packets: u32,

    /// Total received packets (packets that have been ACKed)
    pub recvd_packets: u32,
}

impl SenderMetrics {
    pub fn new() -> Self {
        Self {
            rtt: TimeSpan::from_micros(10_000),
            rtt_var: TimeSpan::from_micros(0),
            pkt_arr_rate: 0,
            est_link_cap: 0,
            lost_packets: 0,
            retrans_packets: 0,
            recvd_packets: 0,
        }
    }
}

#[derive(Debug)]
pub struct Sender {
    settings: ConnectionSettings,
    status: ConnectionStatus,
    handshake: Handshake,
    send_buffer: SendBuffer,
    snd_timer: Timer,
    congestion_control: SenderCongestionControl,
    /// The ack sequence number that an ack2 has been sent for + 1
    next_acked_ack: FullAckSeqNumber,
    output: Output,
    metrics: SenderMetrics,
}

impl Default for SenderMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender {
    pub fn new(settings: ConnectionSettings, handshake: Handshake) -> Self {
        Self {
            settings: settings.clone(),
            status: ConnectionStatus::Open(settings.send_tsbpd_latency),
            handshake,
            send_buffer: SendBuffer::new(&settings),
            snd_timer: Timer::new(Duration::from_millis(1), settings.socket_start_time),
            congestion_control: SenderCongestionControl::new(LiveDataRate::Unlimited, None),
            next_acked_ack: FullAckSeqNumber::INITIAL,
            output: Output::new(&settings),
            metrics: SenderMetrics::new(),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.status.is_closed()
    }

    pub fn is_flushed(&self) -> bool {
        self.send_buffer.is_flushed() && self.output.is_empty()
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn handle_close(&mut self, now: Instant) {
        self.status.shutdown(now);
    }

    pub fn handle_data(&mut self, data: (Instant, Bytes), now: Instant) {
        let data_length = data.1.len() as u64;
        let packets = self.send_buffer.push_data(data);
        self.congestion_control.on_input(now, packets, data_length);
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        let to = self.settings.remote;
        self.output.pop_packet().map(move |packet| (packet, to))
    }

    pub fn check_timers(&mut self, now: Instant) {
        if let Some(exp_time) = self.snd_timer.check_expired(now) {
            self.on_snd_event(exp_time);
        }

        self.output.check_timers(now);

        // don't return close until fully flushed
        let flushed = self.is_flushed();
        if self.status.check_shutdown(now, || flushed) {
            let control = ControlTypes::Shutdown;
            self.output.send_control(now, control);
        }
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        if !self.send_buffer.has_packets_to_send() {
            self.output.next_timer(now)
        } else {
            min(
                max(now, self.snd_timer.next_instant()),
                self.output.next_timer(now),
            )
        }
    }

    fn on_snd(&mut self, now: Instant) {
        //   1) If the sender's loss list is not empty, retransmit the first
        //      packet in the list and remove it from the list. Go to 5).
        //
        // NOTE: the reference implementation doesn't jump to 5), so we don't either
        if let Some(p) = self.send_buffer.pop_next_lost_packet() {
            debug!(
                "{:?}|{:?} sending packet in loss list, seq={:?}",
                TimeSpan::from_interval(self.settings.socket_start_time, now),
                self.settings.local_sockid,
                p.seq_number
            );
            self.send_data(p, now);
        }
        //   2) In messaging mode, if the packets have been in the loss list for a
        //      time more than the application specified TTL, send a message drop
        //      request and remove all related packets from the loss list. Go to
        //      1).
        else if self.send_buffer.has_packets_to_drop(now) {
            for dropped in self.send_buffer.drop_too_late_packets(now) {
                self.metrics.lost_packets += dropped.last - dropped.first;
                self.output.send_control(
                    now,
                    DropRequest {
                        msg_to_drop: dropped.msg,
                        first: dropped.first,
                        last: dropped.last,
                    },
                );
            }
        }
        //   3) Wait until there is application data to be sent.
        else if !self.send_buffer.has_packets_to_send() && !self.status.should_drain() {
        }
        //   4)
        //        a. If the number of unacknowledged packets exceeds the
        //           flow/congestion window size, wait until an ACK comes. Go to
        //           1).
        // TODO: account for looping here <--- WAT?
        else if self.send_buffer.number_of_unacked_packets()
            > self.congestion_control.window_size()
        {
            debug!(
                "{:?}|{:?}|sender flow window exceeded window_size={}, unacked_pkts={}",
                TimeSpan::from_interval(self.settings.socket_start_time, now),
                self.settings.local_sockid,
                self.congestion_control.window_size(),
                self.send_buffer.number_of_unacked_packets(),
            );
        //        b. Pack a new data packet and send it out.
        } else if let Some(p) = self.send_buffer.pop_next_packet() {
            self.send_data(p, now);

            //   5) If the sequence number of the current packet is 16n, where n is an
            //      integer, go to 2).
            if let Some(p) = self.send_buffer.pop_next_16n_packet() {
                //      NOTE: to get the closest timing, we ignore congestion control
                //      and send the 16th packet immediately, instead of proceeding to step 2
                self.send_data(p, now);
            }
        } else if let Some(packet) = self.send_buffer.flush_on_close(self.status.should_drain()) {
            self.send_data(packet, now);
        }

        //   6) Wait (SND - t) time, where SND is the inter-packet interval
        //      updated by congestion control and t is the total time used by step
        //      1 to step 5. Go to 1).

        // NOTE: because this SND event handler code only runs when SND is triggered,
        // exiting this SND event handler will satisfy 6), though we'll update SND as
        // well to ensure congestion control is respected.

        let period = self.congestion_control.snd_period();
        self.snd_timer.set_period(period);
    }

    pub fn handle_ack_packet(&mut self, now: Instant, info: AckControlInfo) {
        if let Some((acknowledged_packets, recovered_packets)) = self
            .send_buffer
            .update_largest_acked_seq_number(info.ack_number())
        {
            // 1) Update the largest acknowledged sequence number, which is the ACK number
            self.metrics.recvd_packets += acknowledged_packets;
            self.metrics.retrans_packets += recovered_packets;

            // 6) If this is a Light ACK, stop.
            if let AckControlInfo::FullSmall {
                ack_number: _,
                rtt,
                rtt_variance,
                buffer_available: _,
                full_ack_seq_number: Some(ack_seq_num),
                packet_recv_rate: Some(packet_recv_rate),
                est_link_cap: Some(est_link_cap),
                data_recv_rate: _,
            } = info
            {
                // 3) Update RTT and RTTVar.
                self.metrics.rtt = rtt;
                self.metrics.rtt_var = rtt_variance;

                if ack_seq_num < self.next_acked_ack {
                    debug!(
                        "{:?}|{:?}|sender invalid ACK ack_seq_num:{:?} next:{:?}",
                        TimeSpan::from_interval(self.settings.socket_start_time, now),
                        self.settings.local_sockid,
                        ack_seq_num,
                        self.next_acked_ack,
                    );
                    return;
                }

                // 1) Update the largest acknowledged sequence number, which is the ACK number
                self.next_acked_ack = ack_seq_num + 1;

                // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
                let control = ControlTypes::Ack2(ack_seq_num);
                self.output.send_control(now, control);

                // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

                // 5) Update flow window size.
                self.congestion_control.on_ack();

                // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
                //    value carried in the ACK.
                self.metrics.pkt_arr_rate =
                    self.metrics.pkt_arr_rate / 8 * 7 + packet_recv_rate / 8;

                // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
                //    the value carried in the ACK.
                self.metrics.est_link_cap = (self
                    .metrics
                    .est_link_cap
                    .saturating_mul(7)
                    .saturating_add(est_link_cap))
                    / 8;
            }
        }
    }

    pub fn handle_shutdown_packet(&mut self, now: Instant) {
        self.status.drain(now);
    }

    pub fn handle_nak_packet(&mut self, nak: CompressedLossList) {
        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
        self.send_buffer.add_to_loss_list(nak);

        // 2) Update the SND period by rate control (see section 3.6).
        // NOTE: NAK does not directly influence Live congestion control
        // update CC
        // if let Some(last_packet) = self.loss_list.back() {
        //     self.congestion_control.on_nak(last_packet.seq_number);
        // }

        // 3) Reset the EXP time variable.
        // NOTE: EXP is reset elsewhere
    }

    pub fn handle_handshake_packet(&mut self, handshake: HandshakeControlInfo, now: Instant) {
        if let Some(control_type) = self.handshake.handle_handshake(handshake) {
            let control = control_type;
            self.output.send_control(now, control);
        }
    }

    fn on_snd_event(&mut self, now: Instant) {
        self.snd_timer.reset(now);
        self.on_snd(now);
    }

    fn send_data(&mut self, p: DataPacket, now: Instant) {
        self.congestion_control.on_packet_sent();
        self.output.send_data(now, p);
    }
}
