use crate::loss_compression::decompress_loss_list;
use crate::packet::{ControlTypes, HandshakeControlInfo, PacketLocation, SrtControlPacket};
use crate::protocol::{Handshake, TimeBase, TimeStamp};
use crate::Packet::*;
use crate::{
    CCData, CongestCtrl, ConnectionSettings, ControlPacket, DataPacket, MsgNumber, Packet,
    SeqNumber, SocketID, SrtCongestCtrl,
};
use bytes::Bytes;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct TransmitBuffer {
    remote_sockid: SocketID,
    max_packet_size: usize,
    time_base: TimeBase,

    /// The list of packets to transmit
    buffer: VecDeque<DataPacket>,

    /// The sequence number for the next data packet
    next_seq_number: SeqNumber,

    /// The message number for the next message
    next_message_number: MsgNumber,
}

impl TransmitBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_sockid: settings.remote_sockid,
            max_packet_size: settings.max_packet_size as usize,
            time_base: TimeBase::from_raw(settings.socket_start_time),
            buffer: Default::default(),
            next_seq_number: settings.init_seq_num,
            next_message_number: MsgNumber::new_truncate(0),
        }
    }

    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets
    pub fn push_data(&mut self, data: (Bytes, Instant)) {
        let (mut payload, time) = data;
        let mut location = PacketLocation::FIRST | PacketLocation::LAST;
        while !payload.is_empty() {
            // if we need to break this packet up
            if payload.len() > self.max_packet_size {
                let slice = payload.slice(self.max_packet_size..payload.len());

                self.begin_transmit(time, slice, location);

                location = PacketLocation::empty();
                payload = payload.slice(0..self.max_packet_size)
            } else {
                location = location | PacketLocation::LAST;
                self.begin_transmit(time, payload, location);
                break;
            }
        }
    }

    fn begin_transmit(&mut self, time: Instant, payload: Bytes, location: PacketLocation) {
        let packet = DataPacket {
            dest_sockid: self.remote_sockid,
            in_order_delivery: false, // TODO: research this
            message_loc: location,
            // if this marks the beginning of the next message, get a new message number, else don't
            message_number: if location == PacketLocation::FIRST {
                self.get_new_message_number()
            } else {
                self.latest_message_number()
            },
            seq_number: self.get_new_sequence_number(),
            timestamp: self.time_base.timestamp_from(time),
            payload,
        };

        self.buffer.push_back(packet)
    }

    pub fn pop_front(&mut self) -> Option<DataPacket> {
        self.buffer.pop_front()
    }

    pub fn front(&self) -> Option<&DataPacket> {
        self.buffer.front()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn latest_message_number(&self) -> MsgNumber {
        self.next_message_number - 1
    }

    pub fn latest_seqence_number(&self) -> SeqNumber {
        self.next_seq_number - 1
    }

    pub fn next_seqence_number(&self) -> SeqNumber {
        self.next_seq_number
    }

    pub fn timestamp_now(&self) -> TimeStamp {
        self.time_base.timestamp_now()
    }

    /// Gets the next available message number
    fn get_new_message_number(&mut self) -> MsgNumber {
        self.next_message_number += 1;
        self.next_message_number - 1
    }

    /// Gets the next avilabe packet sequence number
    fn get_new_sequence_number(&mut self) -> SeqNumber {
        // this does looping for us
        self.next_seq_number += 1;
        self.next_seq_number - 1
    }
}

struct SendBuffer {
    /// The buffer to store packets for retransmision, sorted chronologically
    buffer: VecDeque<DataPacket>,

    /// The first sequence number in buffer, so seq number i would be found at
    /// buffer[i - first_seq]
    first_seq: SeqNumber,
}

impl SendBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            buffer: Default::default(),
            first_seq: settings.init_seq_num,
        }
    }

    pub fn release_acknowledged_packets(&mut self, acknowledged: SeqNumber) {
        while acknowledged > self.first_seq {
            self.buffer.pop_front();
            self.first_seq += 1;
        }
    }

    pub fn get<'a, I: Iterator<Item = SeqNumber> + 'a>(
        &'a self,
        numbers: I,
    ) -> impl Iterator<Item = Result<&'a DataPacket, SeqNumber>> + 'a {
        numbers.map(
            move |number| match self.buffer.get((number - self.first_seq) as usize) {
                Some(p) => Ok(p),
                None => Err(number),
            },
        )
    }

    pub fn push_back(&mut self, data: DataPacket) {
        self.buffer.push_back(data);
    }
}

pub struct LossList {
    pub list: VecDeque<DataPacket>,
}

impl LossList {
    pub fn new(_settings: &ConnectionSettings) -> Self {
        Self {
            list: VecDeque::new(),
        }
    }

    pub fn push_back(&mut self, packet: DataPacket) {
        self.list.push_back(packet);
    }

    pub fn pop_front(&mut self) -> Option<DataPacket> {
        self.list.pop_front()
    }

    pub fn remoeve_acknowledged_packets(&mut self, acknowledged: SeqNumber) -> u32 {
        let mut retransmited_packets = 0;
        while let Some(x) = self.list.front() {
            if acknowledged > x.seq_number {
                let _ = self.pop_front();
                // this means a packet was lost then retransmitted
                retransmited_packets += 1;
            } else {
                break;
            }
        }
        retransmited_packets
    }

    pub fn back(&self) -> Option<&DataPacket> {
        self.list.back()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

#[derive(Debug)]
pub enum SenderError {}

pub type SenderResult = Result<Option<(ControlPacket, SocketAddr)>, SenderError>;

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
pub enum SenderAlgorithmStep {
    Step1,
    Step2(Instant),
    Step3(Instant),
    Step4(Instant),
    Step5(Instant),
    Step6(Instant),
}

#[derive(Debug, Clone)]
pub enum SenderAlgorithmAction {
    Continue,
    WaitUnitlAck,
    WaitUntilData,
    WaitUntil(Instant),
    SendControl((ControlPacket, SocketAddr)),
    SendData((DataPacket, SocketAddr)),
    Close,
}

pub struct Sender {
    close: bool,

    current_algorithm_step: SenderAlgorithmStep,

    handshake: Handshake,

    /// The settings, including remote sockid and address
    settings: ConnectionSettings,

    metrics: SenderMetrics,

    /// The buffer to store packets for retransmission, sorted chronologically
    send_buffer: SendBuffer,

    /// The buffer to store the next control packet
    control_buffer: Option<ControlPacket>,

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

    /// The congestion control
    congestion_control: SrtCongestCtrl,
}

impl Sender {
    pub fn new(
        settings: ConnectionSettings,
        handshake: Handshake,
        congestion_control: SrtCongestCtrl,
    ) -> Self {
        Self {
            close: false,
            current_algorithm_step: SenderAlgorithmStep::Step1,
            handshake,
            settings,
            metrics: SenderMetrics::new(),
            send_buffer: SendBuffer::new(&settings),
            loss_list: LossList::new(&settings),
            lr_acked_packet: settings.init_seq_num,
            lr_acked_ack: -1, // TODO: why magic number?
            congestion_control,
            control_buffer: None,
            transmit_buffer: TransmitBuffer::new(&settings),
        }
    }

    pub fn next_algorithm_action<Now: Fn() -> Instant>(
        &mut self,
        now: Now,
    ) -> (SenderAlgorithmStep, SenderAlgorithmAction) {
        use SenderAlgorithmAction::*;
        use SenderAlgorithmStep::*;

        if let Some(packet) = self.control_buffer.take() {
            return (
                self.current_algorithm_step.clone(),
                SendControl((packet, self.settings.remote)),
            );
        }

        let current_algorithm_step = self.current_algorithm_step.clone();
        //   Data Sending Algorithm:
        let (next_action, next_step) = match current_algorithm_step {
            //   1) If the sender's loss list is not empty, retransmit the first
            //      packet in the list and remove it from the list. Go to 5).
            Step1 => match self.pop_loss_list() {
                Some(packet) => (SendData((packet, self.settings.remote)), Step5(now())),
                None => (Continue, Step2(now())),
            },

            // TODO: what is messaging mode?
            //
            //   2) In messaging mode, if the packets has been the loss list for a
            //      time more than the application specified TTL, send a message drop
            //      request and remove all related packets from the loss list. Go to
            //      1).
            Step2(t) => match self.trim_loss_list() {
                Some(packet) => (SendControl(packet), Step1),
                None => (Continue, Step3(t)),
            },

            //   3) Wait until there is application data to be sent.
            Step3(t) => match self.peek_transmit_buffer() {
                None => (WaitUntilData, Step3(t)),
                Some(_) => (Continue, Step4(t)),
            },

            //   4)
            //        a. If the number of unacknowledged packets exceeds the
            //           flow/congestion window size, wait until an ACK comes. Go to
            //           1).
            //        b. Pack a new data packet and send it out.
            Step4(t) => match self.pop_transmit_buffer() {
                None => (WaitUnitlAck, Step1),
                Some(packet) => (SendData((packet, self.settings.remote)), Step5(t)),
            },

            //   5) If the sequence number of the current packet is 16n, where n is an
            //      integer, go to 2).
            Step5(t) => match self.peek_transmit_buffer().map(|p| p.seq_number % 16) {
                Some(0) => (Continue, Step2(t)),
                //                Some(_) => (Continue, Step4(t)),
                _ => (Continue, Step6(t)),
            },

            //   6) Wait (SND - t) time, where SND is the inter-packet interval
            //      updated by congestion control and t is the total time used by step
            //      1 to step 5. Go to 1).
            Step6(t) => (WaitUntil(t + self.congestion_control.SDN()), Step1),
        };

        self.current_algorithm_step = next_step;

        (current_algorithm_step, next_action)
    }

    pub fn handle_close(&mut self, now: Instant) -> SenderResult {
        self.close = true;
        self.send_control(ControlTypes::Shutdown, now)
    }

    pub fn handle_send_rx(&mut self, data: (Bytes, Instant), _now: Instant) -> SenderResult {
        let (b, t) = data;
        self.transmit_buffer.push_data((b, t));
        Ok(None)
    }

    pub fn handle_timer(&mut self, _time: Instant) -> SenderResult {
        // TODO: is the still needed?
        Ok(None)
    }

    pub fn handle_packet(&mut self, packet: (Packet, SocketAddr), now: Instant) -> SenderResult {
        // TODO: regect/discard/report packets from invalid hosts
        match packet {
            (Control(control), _from) => self.handle_control_packet(control, now),
            (Data(data), _from) => self.handle_data_packet(data, now),
        }
    }

    pub fn peek_transmit_buffer(&mut self) -> Option<&DataPacket> {
        self.transmit_buffer.front()
    }

    pub fn pop_transmit_buffer(&mut self) -> Option<DataPacket> {
        let packet = self.transmit_buffer.pop_front()?;
        self.send_buffer.push_back(packet.clone());
        Some(packet)
    }

    pub fn pop_loss_list(&mut self) -> Option<DataPacket> {
        self.loss_list.pop_front()
    }

    pub fn trim_loss_list(&mut self) -> Option<(ControlPacket, SocketAddr)> {
        // TODO: trim until empty
        //        let packet = self.loss_list.pop_front();
        //        Some((Packet::Data(packet?), self.settings.remote))
        None
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
            ControlTypes::Ack2(_) => Ok(None), // warn!("Sender received ACK2, unusual"),
            ControlTypes::DropRequest { .. } => unimplemented!(),
            ControlTypes::Handshake(shake) => self.handle_handshake_packet(shake),
            // TODO: reset EXP-ish

            // TODO: case UMSG_CGWARNING: // 100 - Delay Warning
            //            // One way packet delay is increasing, so decrease the sending rate
            //            ControlTypes::DelayWarning?

            // TODO: case UMSG_LOSSREPORT: // 011 - Loss Report is this Nak?
            // TODO: case UMSG_DROPREQ: // 111 - Msg drop request
            // TODO: case UMSG_PEERERROR: // 1000 - An error has happened to the peer side
            // TODO: case UMSG_EXT: // 0x7FFF - reserved and user defined messages
            ControlTypes::Nak(nack) => self.handle_nack_packet(nack),
            ControlTypes::Shutdown => Ok(None), // TODO: re-introduce state enum?
            ControlTypes::Srt(srt_packet) => self.handle_srt_control_packet(srt_packet),
            // The only purpose of keep-alive packet is to tell that the peer is still alive
            // nothing needs to be done.
            ControlTypes::KeepAlive => Ok(None),
        }
    }

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
            return Ok(None);
        }

        if ack_seq_num <= self.lr_acked_ack {
            // warn!("Ack sequence number '{}' less than or equal to the previous one recieved: '{}'", ack_seq_num, self.lr_acked_ack);
            return Ok(None);
        }
        self.lr_acked_ack = ack_seq_num;

        // update the packets received count
        self.metrics.recvd_packets += ack_number - self.lr_acked_packet;

        // 1) Update the largest acknowledged sequence number, which is the ACK number
        self.lr_acked_packet = ack_number;

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
        self.metrics.retrans_packets += self.loss_list.remoeve_acknowledged_packets(ack_number);

        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
        self.send_control(ControlTypes::Ack2(ack_seq_num), now)
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
                Err(_n) => {
                    //debug!("NAK received for packet {} that's not in the buffer, maybe it's already been ACKed", n);
                    return Ok(None);
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
        Ok(None)
    }

    fn handle_handshake_packet(&mut self, handshake: HandshakeControlInfo) -> SenderResult {
        self.handshake
            .handle_handshake::<SenderError>(self.settings.remote, handshake)
    }

    fn handle_srt_control_packet(&mut self, packet: SrtControlPacket) -> SenderResult {
        use self::SrtControlPacket::*;

        match packet {
            HandshakeRequest(_) | HandshakeResponse(_) => {
                // warn!("Received handshake request or response for an already setup SRT connection")
            }
            _ => unimplemented!(),
        }

        Ok(None)
    }

    fn handle_data_packet(&mut self, _packet: DataPacket, _now: Instant) -> SenderResult {
        Ok(None)
    }

    fn send_control(&mut self, control: ControlTypes, now: Instant) -> SenderResult {
        self.control_buffer = Some(ControlPacket {
            timestamp: self.transmit_buffer.time_base.timestamp_from(now),
            dest_sockid: self.settings.remote_sockid,
            control_type: control,
        });
        Ok(None)
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
}
