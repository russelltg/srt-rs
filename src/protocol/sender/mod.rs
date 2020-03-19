mod buffers;
mod congestion_control;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::debug;
use log::{trace, warn};

use crate::loss_compression::decompress_loss_list;
use crate::packet::{ControlTypes, HandshakeControlInfo, SrtControlPacket};
use crate::protocol::handshake::Handshake;
use crate::protocol::time::Timer;
use crate::{CCData, ConnectionSettings, ControlPacket, DataPacket, Packet, SeqNumber};

use buffers::*;
use congestion_control::{LiveDataRate, SenderCongestionControl};

#[derive(Debug)]
pub enum SenderError {}

pub type SenderResult = Result<(), SenderError>;

#[derive(Debug, Clone, Copy)]
pub struct SenderMetrics {
    /// Round trip time, in microseconds
    pub rtt: i32,

    /// Round trip time variance
    pub rtt_var: i32,

    /// packet arrival rate
    pub pkt_arr_rate: i32,

    /// estimated link capacity
    pub est_link_cap: i32,

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
            rtt: 10_000,
            rtt_var: 0,
            pkt_arr_rate: 0,
            est_link_cap: 0,
            lost_packets: 0,
            retrans_packets: 0,
            recvd_packets: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SenderAlgorithmAction {
    WaitUntilAck,
    WaitForData,
    WaitUntil(Instant),
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SenderAlgorithmStep {
    Step1,
    Step6,
}

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
    lr_acked_ack: i32,

    step: SenderAlgorithmStep,

    snd_timer: Timer,

    close: bool,
}

impl Default for SenderMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender {
    pub fn new(settings: ConnectionSettings, handshake: Handshake) -> Self {
        Self {
            settings,
            handshake,
            congestion_control: SenderCongestionControl::new(LiveDataRate::Unlimited, None),
            metrics: SenderMetrics::new(),
            send_buffer: SendBuffer::new(&settings),
            loss_list: LossList::new(&settings),
            lr_acked_packet: settings.init_seq_num,
            lr_acked_ack: -1, // TODO: why magic number?
            output_buffer: VecDeque::new(),
            transmit_buffer: TransmitBuffer::new(&settings),
            step: SenderAlgorithmStep::Step1,
            snd_timer: Timer::new(Duration::from_millis(1), settings.socket_start_time),
            close: false,
        }
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn metrics(&self) -> SenderMetrics {
        self.metrics
    }

    pub fn handle_close(&mut self, now: Instant) {
        if !self.close {
            self.close = true;
            self.send_control(ControlTypes::Shutdown, now);
        }
    }

    pub fn handle_data(&mut self, data: (Instant, Bytes), now: Instant) {
        let data_length = data.1.len();
        let packet_count = self.transmit_buffer.push_data(data);
        self.congestion_control
            .on_input(now, packet_count, data_length);
    }

    pub fn handle_snd_timer(&mut self, now: Instant) {
        self.snd_timer.reset(now);
        self.step = SenderAlgorithmStep::Step1;
    }

    pub fn handle_packet(&mut self, packet: (Packet, SocketAddr), now: Instant) -> SenderResult {
        let (packet, from) = packet;

        // TODO: record/report packets from invalid hosts?
        if from != self.settings.remote {
            return Ok(());
        }

        match packet {
            Packet::Control(control) => self.handle_control_packet(control, now),
            Packet::Data(data) => self.handle_data_packet(data, now),
        }
    }

    pub fn is_flushed(&mut self) -> bool {
        self.loss_list.is_empty()
            && self.transmit_buffer.is_empty()
            && self.lr_acked_packet == self.transmit_buffer.next_sequence_number
            && self.send_buffer.is_empty()
            && self.output_buffer.is_empty()
    }

    pub fn pop_output(&mut self) -> Option<(Packet, SocketAddr)> {
        let to = self.settings.remote;
        self.output_buffer
            .pop_front()
            .map(move |packet| (packet, to))
    }

    pub fn next_action(&mut self) -> SenderAlgorithmAction {
        use SenderAlgorithmAction::*;
        use SenderAlgorithmStep::*;

        if self.close {
            return Close;
        }

        if self.step == Step6 {
            return WaitUntil(self.snd_timer.next_instant());
        }

        //   1) If the sender's loss list is not empty, retransmit the first
        //      packet in the list and remove it from the list. Go to 5).
        if let Some(p) = self.loss_list.pop_front() {
            debug!("Sending packet in loss list, seq={:?}", p.seq_number);
            self.send_data(p);

            // TODO: returning here will result in sending all the packets in the loss
            //       list before progressing further through the sender algorithm. This
            //       appears to be inconsistent with the UDT spec. Is it consistent
            //       with the reference implementation?
            return WaitForData;
        }
        // TODO: what is messaging mode?
        // TODO: I honestly don't know what this means
        //
        //   2) In messaging mode, if the packets has been the loss list for a
        //      time more than the application specified TTL, send a message drop
        //      request and remove all related packets from the loss list. Go to
        //      1).

        //   3) Wait until there is application data to be sent.
        else if self.transmit_buffer.is_empty() {
            // TODO: the spec for 3) seems to suggest waiting at here for data,
            //       but if execution doesn't jump back to Step1, then many of
            //       the tests don't pass... WAT?
            return WaitForData;
        }
        //   4)
        //        a. If the number of unacknowledged packets exceeds the
        //           flow/congestion window size, wait until an ACK comes. Go to
        //           1).
        //        b. Pack a new data packet and send it out.
        // TODO: account for looping here <--- WAT?
        else if self.lr_acked_packet
            < self.transmit_buffer.next_sequence_number - self.congestion_control.window_size()
        {
            // flow window exceeded, wait for ACK
            trace!("Flow window exceeded lr_acked={:?}, next_seq={:?}, window_size={}, next_seq-window={:?}",
                   self.lr_acked_packet,
                   self.transmit_buffer.next_sequence_number,
                   self.congestion_control.window_size(),
                   self.transmit_buffer.next_sequence_number - self.congestion_control.window_size());

            return WaitUntilAck;
        } else if let Some(p) = self.pop_transmit_buffer() {
            self.send_data(p);
        }

        //   5) If the sequence number of the current packet is 16n, where n is an
        //      integer, go to 2).
        if let Some(p) = self.pop_transmit_buffer_16n() {
            //      NOTE: to get the closest timing, we ignore congestion control
            //      and send the 16th packet immediately, instead of proceeding to step 2
            self.send_data(p);
        }

        //   6) Wait (SND - t) time, where SND is the inter-packet interval
        //      updated by congestion control and t is the total time used by step
        //      1 to step 5. Go to 1).
        self.step = Step6;
        self.snd_timer
            .set_period(self.congestion_control.snd_period());
        WaitUntil(self.snd_timer.next_instant())
    }

    fn handle_data_packet(&mut self, _packet: DataPacket, _now: Instant) -> SenderResult {
        Ok(())
    }

    fn handle_control_packet(&mut self, packet: ControlPacket, now: Instant) -> SenderResult {
        match packet.control_type {
            ControlTypes::Ack {
                ack_seq_num,
                ack_number,
                rtt,
                rtt_variance,
                packet_recv_rate,
                est_link_cap,
                ..
            } => self.handle_ack_packet(
                now,
                ack_seq_num,
                ack_number,
                rtt,
                rtt_variance,
                packet_recv_rate,
                est_link_cap,
            ),
            ControlTypes::Ack2(_) => {
                warn!("Sender received ACK2, unusual");
                Ok(())
            }
            ControlTypes::DropRequest { .. } => unimplemented!(),
            ControlTypes::Handshake(shake) => self.handle_handshake_packet(shake, now),
            // TODO: reset EXP-ish

            // TODO: case UMSG_CGWARNING: // 100 - Delay Warning
            //            // One way packet delay is increasing, so decrease the sending rate
            //            ControlTypes::DelayWarning?

            // TODO: case UMSG_LOSSREPORT: // 011 - Loss Report is this Nak?
            // TODO: case UMSG_DROPREQ: // 111 - Msg drop request
            // TODO: case UMSG_PEERERROR: // 1000 - An error has happened to the peer side
            // TODO: case UMSG_EXT: // 0x7FFF - reserved and user defined messages
            ControlTypes::Nak(nack) => self.handle_nack_packet(nack),
            ControlTypes::Shutdown => self.handle_shutdown_packet(),
            ControlTypes::Srt(srt_packet) => self.handle_srt_control_packet(srt_packet),
            // The only purpose of keep-alive packet is to tell that the peer is still alive
            // nothing needs to be done.
            // TODO: is this actually true? check reference implementation
            ControlTypes::KeepAlive => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_ack_packet(
        &mut self,
        now: Instant,
        ack_seq_num: i32,
        ack_number: SeqNumber,
        rtt: Option<i32>,
        rtt_variance: Option<i32>,
        packet_recv_rate: Option<i32>,
        est_link_cap: Option<i32>,
    ) -> SenderResult {
        // if this ack number is less than or equal to
        // the largest received ack number, than discard it
        // this can happen thorough packet reordering OR losing an ACK2 packet
        if ack_number <= self.lr_acked_packet {
            return Ok(());
        }

        if ack_seq_num <= self.lr_acked_ack {
            // warn!("Ack sequence number '{}' less than or equal to the previous one recieved: '{}'", ack_seq_num, self.lr_acked_ack);
            return Ok(());
        }
        self.lr_acked_ack = ack_seq_num;

        // update the packets received count
        self.metrics.recvd_packets += ack_number - self.lr_acked_packet;

        // 1) Update the largest acknowledged sequence number, which is the ACK number
        self.lr_acked_packet = ack_number;

        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
        self.send_control(ControlTypes::Ack2(ack_seq_num), now);

        // 3) Update RTT and RTTVar.
        self.metrics.rtt = rtt.unwrap_or(0);
        self.metrics.rtt_var = rtt_variance.unwrap_or(0);

        // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
        // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

        // 5) Update flow window size.
        {
            let cc_info = self.make_cc_info();
            self.congestion_control.on_ack(&cc_info);
        }

        // 6) If this is a Light ACK, stop.
        // TODO: wat

        // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
        //    value carried in the ACK.
        self.metrics.pkt_arr_rate =
            self.metrics.pkt_arr_rate / 8 * 7 + packet_recv_rate.unwrap_or(0) / 8;

        // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
        //    the value carried in the ACK.
        self.metrics.est_link_cap = (self.metrics.est_link_cap * 7 + est_link_cap.unwrap_or(0)) / 8;

        // 9) Update sender's buffer (by releasing the buffer that has been
        //    acknowledged).
        self.send_buffer.release_acknowledged_packets(ack_number);

        // 10) Update sender's loss list (by removing all those that has been
        //     acknowledged).
        self.metrics.retrans_packets += self.loss_list.remove_acknowledged_packets(ack_number);

        Ok(())
    }

    fn handle_shutdown_packet(&mut self) -> SenderResult {
        self.close = true;
        Ok(())
    }

    fn handle_nack_packet(&mut self, nack: Vec<u32>) -> SenderResult {
        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
        // 2) Update the SND period by rate control (see section 3.6).
        // 3) Reset the EXP time variable.

        for lost in self
            .send_buffer
            .get(decompress_loss_list(nack.iter().cloned()))
        {
            let packet = match lost {
                Ok(p) => p,
                Err(n) => {
                    debug!("NAK received for packet {} that's not in the buffer, maybe it's already been ACKed", n);
                    return Ok(());
                }
            };

            self.loss_list.push_back(packet.clone());
        }

        // update CC
        if let Some(last_packet) = self.loss_list.back() {
            let cc_info = self.make_cc_info();
            self.congestion_control
                .on_nak(last_packet.seq_number, &cc_info);
        }

        // TODO: reset EXP
        Ok(())
    }

    fn handle_handshake_packet(
        &mut self,
        handshake: HandshakeControlInfo,
        now: Instant,
    ) -> SenderResult {
        if let Some(control_type) = self.handshake.handle_handshake(handshake) {
            self.send_control(control_type, now);
        }
        Ok(())
    }

    fn handle_srt_control_packet(&mut self, packet: SrtControlPacket) -> SenderResult {
        use self::SrtControlPacket::*;

        match packet {
            HandshakeRequest(_) | HandshakeResponse(_) => {
                warn!("Received handshake request or response for an already setup SRT connection")
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn make_cc_info(&self) -> CCData {
        CCData {
            est_bandwidth: self.metrics.est_link_cap,
            max_segment_size: self.settings.max_packet_size,
            latest_seq_num: Some(self.transmit_buffer.latest_seqence_number()),
            packet_arr_rate: self.metrics.pkt_arr_rate,
            rtt: Duration::from_micros(self.metrics.rtt as u64),
        }
    }

    fn pop_transmit_buffer(&mut self) -> Option<DataPacket> {
        let packet = self.transmit_buffer.pop_front()?;
        self.congestion_control.on_packet_sent(&self.make_cc_info());
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
        self.output_buffer.push_back(Packet::Control(ControlPacket {
            timestamp: self.transmit_buffer.timestamp_from(now),
            dest_sockid: self.settings.remote_sockid,
            control_type: control,
        }));
    }

    fn send_data(&mut self, p: DataPacket) {
        self.output_buffer.push_back(Packet::Data(p));
    }
}
