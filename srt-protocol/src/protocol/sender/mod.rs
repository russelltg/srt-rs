mod buffers;
mod congestion_control;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::debug;
use log::trace;

use super::TimeSpan;
use crate::packet::{AckControlInfo, ControlTypes, FullAck, HandshakeControlInfo};
use crate::packet::{AckSeqNumber, CompressedLossList};
use crate::protocol::handshake::Handshake;
use crate::protocol::Timer;
use crate::{ConnectionSettings, ControlPacket, DataPacket, Packet, SeqNumber};

use crate::connection::ConnectionStatus;
use crate::packet::ControlTypes::KeepAlive;
use buffers::*;
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
    /// The settings, including remote sockid and address
    settings: ConnectionSettings,

    handshake: Handshake,

    /// The congestion control
    congestion_control: SenderCongestionControl,

    metrics: SenderMetrics,

    /// The buffer to store packets for retransmission, sorted chronologically
    send_buffer: SendBuffer,

    /// The buffer to store the next control packet
    output_buffer: VecDeque<Packet>,

    /// The buffer to store packets for transmission
    transmit_buffer: TransmitBuffer,

    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    loss_list: LossList,

    /// The sequence number of the largest acknowledged packet + 1
    lr_acked_packet: SeqNumber,

    /// The ack sequence number that an ack2 has been sent for
    lr_acked_ack: AckSeqNumber,

    snd_timer: Timer,
    // this isn't in the spec, but it's in the reference implementation
    // https://github.com/Haivision/srt/blob/1d7b391905d7e344d80b86b39ac5c90fda8764a9/srtcore/core.cpp#L10610-L10614
    keepalive_timer: Timer,

    status: ConnectionStatus,
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
            handshake,
            congestion_control: SenderCongestionControl::new(LiveDataRate::Unlimited, None),
            metrics: SenderMetrics::new(),
            send_buffer: SendBuffer::new(&settings),
            loss_list: LossList::new(&settings),
            lr_acked_packet: settings.init_seq_num,
            lr_acked_ack: 0.into(),
            output_buffer: VecDeque::new(),
            transmit_buffer: TransmitBuffer::new(&settings),
            snd_timer: Timer::new(Duration::from_millis(1), settings.socket_start_time),
            keepalive_timer: Timer::new(Duration::from_secs(1), settings.socket_start_time),
            status: ConnectionStatus::Open(settings.send_tsbpd_latency),
        }
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn handle_close(&mut self, now: Instant) {
        self.status.shutdown(now);
    }

    pub fn handle_data(&mut self, data: (Instant, Bytes), now: Instant) {
        let data_length = data.1.len() as u64;
        let packet_count = self.transmit_buffer.push_message(data) as u64;
        self.congestion_control
            .on_input(now, packet_count, data_length);
    }

    pub fn is_flushed(&self) -> bool {
        debug!(
            "{:?}|{:?}|recv - ll.len()={}, tb.len()={}, lrap={}, nsn={}, sb.len()={}, ob.len()={}",
            TimeSpan::from_interval(self.settings.socket_start_time, Instant::now()),
            self.settings.local_sockid,
            self.loss_list.len(),
            self.transmit_buffer.len(),
            self.lr_acked_packet,
            self.transmit_buffer.next_sequence_number,
            self.send_buffer.len(),
            self.output_buffer.len()
        );
        self.loss_list.is_empty()
            && self.transmit_buffer.is_empty()
            && self.lr_acked_packet == self.transmit_buffer.next_sequence_number
            && self.output_buffer.is_empty()
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        let to = self.settings.remote;
        self.output_buffer
            .pop_front()
            .map(move |packet| (packet, to))
    }

    pub fn check_timers(&mut self, now: Instant) {
        if let Some(exp_time) = self.snd_timer.check_expired(now) {
            self.on_snd_event(exp_time);
        }
        if let Some(exp_time) = self.keepalive_timer.check_expired(now) {
            self.on_keepalive_event(exp_time);
        }

        // don't return close until fully flushed
        let flushed = self.is_flushed();
        if self.status.check_shutdown(now, || flushed) {
            debug!("{:?} sending shutdown", self.settings.local_sockid);
            self.send_control(ControlTypes::Shutdown, now);
        }
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        if self.transmit_buffer.is_empty() && self.loss_list.is_empty() {
            max(now, self.keepalive_timer.next_instant())
        } else {
            min(
                max(now, self.snd_timer.next_instant()),
                max(now, self.keepalive_timer.next_instant()),
            )
        }
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }

    fn on_snd(&mut self, now: Instant) {
        //   1) If the sender's loss list is not empty, retransmit the first
        //      packet in the list and remove it from the list. Go to 5).
        //
        // NOTE: the reference implementation doesn't jump to 5), so we don't either
        if let Some(p) = self.loss_list.pop_front() {
            debug!("Sending packet in loss list, seq={:?}", p.seq_number);
            self.send_data(p, now);
        }
        // TODO: what is messaging mode?
        // TODO: I honestly don't know what this means
        //
        //   2) In messaging mode, if the packets has been the loss list for a
        //      time more than the application specified TTL, send a message drop
        //      request and remove all related packets from the loss list. Go to
        //      1).

        //   3) Wait until there is application data to be sent.
        else if self.transmit_buffer.is_empty() && !self.status.should_drain() {
        }
        //   4)
        //        a. If the number of unacknowledged packets exceeds the
        //           flow/congestion window size, wait until an ACK comes. Go to
        //           1).
        //        b. Pack a new data packet and send it out.
        // TODO: account for looping here <--- WAT?
        else if self.lr_acked_packet
            < self.transmit_buffer.next_sequence_number_to_send()
                - self.congestion_control.window_size()
        {
            // flow window exceeded, wait for ACK
            trace!("Flow window exceeded lr_acked={:?}, next_seq={:?}, window_size={}, next_seq-window={:?}",
                   self.lr_acked_packet,
                   self.transmit_buffer.next_sequence_number,
                   self.congestion_control.window_size(),
                   self.transmit_buffer.next_sequence_number - self.congestion_control.window_size());
        } else if let Some(p) = self.pop_transmit_buffer() {
            self.send_data(p, now);

            //   5) If the sequence number of the current packet is 16n, where n is an
            //      integer, go to 2).
            if let Some(p) = self.pop_transmit_buffer_16n() {
                //      NOTE: to get the closest timing, we ignore congestion control
                //      and send the 16th packet immediately, instead of proceeding to step 2
                self.send_data(p, now);
            }
        } else if let Some(packet) = self.flush_send_buffer_on_close() {
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

    fn flush_send_buffer_on_close(&mut self) -> Option<DataPacket> {
        if self.status.should_drain() && self.send_buffer.len() == 1 {
            self.send_buffer.pop().map(|packet| {
                // sender is closing, there is no need to track ACKs anymore
                self.lr_acked_packet = self.transmit_buffer.next_sequence_number;
                packet
            })
        } else {
            None
        }
    }

    pub fn handle_ack_packet(&mut self, now: Instant, info: AckControlInfo) {
        // if this ack number is less than (but NOT equal--equal could just mean lost ACK2 that needs to be retransmitted)
        // the largest received ack number, than discard it
        // this can happen thorough packet reordering OR losing an ACK2 packet
        if info.ack_number() < self.lr_acked_packet {
            return;
        }

        // This could be either a lite or full ack, we do extra stuff for a full ack

        // 1) Update the largest acknowledged sequence number, which is the ACK number
        self.lr_acked_packet = info.ack_number();

        // update the packets received count
        self.metrics.recvd_packets += info.ack_number() - self.lr_acked_packet;

        // 9) Update sender's buffer (by releasing the buffer that has been
        //    acknowledged).
        self.send_buffer
            .release_acknowledged_packets(info.ack_number());

        // 10) Update sender's loss list (by removing all those that has been
        //     acknowledged).
        self.metrics.retrans_packets += self
            .loss_list
            .remove_acknowledged_packets(info.ack_number());

        if let AckControlInfo::FullSmall {
            ack_number,
            rtt,
            rtt_variance,
            buffer_available,
            full:
                Some(FullAck {
                    ack_seq_num,

                    packet_recv_rate,
                    est_link_cap,
                    data_recv_rate,
                }),
        } = info
        {
            if ack_seq_num <= self.lr_acked_ack {
                // warn!("Ack sequence number '{}' less than or equal to the previous one recieved: '{}'", ack_seq_num, self.lr_acked_ack);
                return;
            }

            self.lr_acked_ack = ack_seq_num;

            // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
            self.send_control(ControlTypes::Ack2(ack_seq_num), now);

            // 3) Update RTT and RTTVar.
            self.metrics.rtt = rtt;
            self.metrics.rtt_var = rtt_variance;

            // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
            // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

            // 5) Update flow window size.
            self.congestion_control.on_ack();

            // 6) If this is a Light ACK, stop.
            // TODO: wat

            // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
            //    value carried in the ACK.
            self.metrics.pkt_arr_rate = self.metrics.pkt_arr_rate / 8 * 7 + packet_recv_rate / 8;

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

    pub fn handle_shutdown_packet(&mut self, now: Instant) {
        self.status.drain(now);
    }

    pub fn handle_nack_packet(&mut self, nack: CompressedLossList) {
        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
        // 2) Update the SND period by rate control (see section 3.6).
        // 3) Reset the EXP time variable.

        for lost in self.send_buffer.get(nack.iter_decompressed()) {
            let packet = match lost {
                Ok(p) => p,
                Err(n) => {
                    debug!("NAK received for packet {} that's not in the buffer, maybe it's already been ACKed", n);
                    return;
                }
            };

            // this has already been ack'd
            if packet.seq_number < self.lr_acked_packet {
                continue;
            }

            self.loss_list.push_back(packet.clone());
        }

        // update CC
        if let Some(last_packet) = self.loss_list.back() {
            self.congestion_control.on_nak(last_packet.seq_number);
        }

        // TODO: reset EXP
    }

    pub fn handle_handshake_packet(&mut self, handshake: HandshakeControlInfo, now: Instant) {
        if let Some(control_type) = self.handshake.handle_handshake(handshake) {
            self.send_control(control_type, now);
        }
    }

    fn on_snd_event(&mut self, now: Instant) {
        self.snd_timer.reset(now);
        self.on_snd(now);
    }

    fn on_keepalive_event(&mut self, now: Instant) {
        self.send_control(KeepAlive, now);
    }

    fn pop_transmit_buffer(&mut self) -> Option<DataPacket> {
        let packet = self.transmit_buffer.pop_front()?;
        self.congestion_control.on_packet_sent();
        self.send_buffer.push_back(packet.clone());
        Some(packet)
    }

    fn pop_transmit_buffer_16n(&mut self) -> Option<DataPacket> {
        match self.transmit_buffer.front().map(|p| p.seq_number % 16) {
            Some(0) => self.pop_transmit_buffer(),
            _ => None,
        }
    }

    fn send_control(&mut self, control: ControlTypes, now: Instant) {
        self.keepalive_timer.reset(now);
        self.output_buffer.push_back(Packet::Control(ControlPacket {
            timestamp: self.transmit_buffer.timestamp_from(now),
            dest_sockid: self.settings.remote_sockid,
            control_type: control,
        }));
    }

    fn send_data(&mut self, p: DataPacket, now: Instant) {
        self.keepalive_timer.reset(now);
        self.output_buffer.push_back(Packet::Data(p));
    }
}
