use {
    bytes::{Bytes, BytesMut}, failure::Error, futures::prelude::*,
    futures_timer::{Delay, Interval}, loss_compression::decompress_loss_list,
    packet::{ControlPacket, ControlTypes, DataPacket, Packet, PacketLocation},
    srt_packet::{SrtControlPacket, SrtHandshake, SrtShakeFlags}, srt_version,
    std::{collections::VecDeque, io::Cursor, net::SocketAddr, time::Duration}, CCData, CongestCtrl,
    ConnectionSettings, MsgNumber, SeqNumber, Stats,
};

pub struct Sender<T, CC> {
    sock: T,

    /// The congestion control
    congest_ctrl: CC,

    /// The settings, including remote sockid and address
    settings: ConnectionSettings,

    /// The list of pending packets
    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets, and the remaining
    /// bits will be put back into pending packets, setting
    /// at_msg_beginning to false
    pending_packets: VecDeque<Bytes>,

    /// True if pending_packets.first() has the entirety of a message, and not
    /// just the last segment.
    at_msg_beginning: bool,

    /// The sequence number for the next data packet
    next_seq_number: SeqNumber,

    /// The message number for the next message
    next_message_number: MsgNumber,

    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    loss_list: VecDeque<DataPacket>,

    /// The buffer to store packets for retransmision, sorted chronologically
    buffer: VecDeque<DataPacket>,

    /// The first sequence number in buffer, so seq number i would be found at
    /// buffer[i - first_seq]
    first_seq: SeqNumber,

    /// The sequence number of the largest acknowledged packet + 1
    lr_acked_packet: SeqNumber,

    /// Round trip time, in microseconds
    rtt: i32,

    /// Round trip time variance
    rtt_var: i32,

    /// packet arrival rate
    pkt_arr_rate: i32,

    /// estimated link capacity
    est_link_cap: i32,

    /// Total lost packets
    lost_packets: u32,

    /// Total retransmitted packets
    retrans_packets: u32,

    /// Total received packets (packets that have been ACKed)
    recvd_packets: u32,

    /// The send timer
    snd_timer: Delay,

    /// The interval to report stats with
    stats_interval: Interval,

    /// Interval to send SRT handshake packets with.
    srt_handshake_interval: Option<Interval>,

    /// Tracks if the sender is closed
    /// This means that `close` has been called and the sender has been flushed,
    /// and it's just waiting for the socket to flush
    closed: bool,
}

impl<T, CC> Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestCtrl,
{
    pub fn new(sock: T, congest_ctrl: CC, settings: ConnectionSettings) -> Sender<T, CC> {
        info!("Sending started to {:?}", settings.remote);

        Sender {
            sock,
            congest_ctrl,
            settings,
            pending_packets: VecDeque::new(),
            at_msg_beginning: true,
            next_seq_number: settings.init_seq_num,
            next_message_number: MsgNumber::new(0),
            loss_list: VecDeque::new(),
            buffer: VecDeque::new(),
            first_seq: settings.init_seq_num,
            lr_acked_packet: settings.init_seq_num,
            rtt: 10_000,
            rtt_var: 0,
            pkt_arr_rate: 0,
            est_link_cap: 0,
            lost_packets: 0,
            retrans_packets: 0,
            recvd_packets: 0,
            snd_timer: Delay::new(Duration::from_millis(1)),
            stats_interval: Interval::new(Duration::from_secs(1)),
            srt_handshake_interval: settings
                .tsbpd_latency
                .map(|_| Interval::new(Duration::from_millis(100))),
            closed: false,
        }
    }

    /// Set the interval to get statistics on
    /// Defaults to one second
    pub fn set_stats_interval(&mut self, interval: Duration) {
        self.stats_interval = Interval::new(interval);
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn remote(&self) -> SocketAddr {
        self.settings.remote
    }

    pub fn stats(&self) -> Stats {
        Stats {
            timestamp: self.get_timestamp(),
            est_link_cap: self.est_link_cap,
            flow_size: self.congest_ctrl.window_size(),
            lost_packets: self.lost_packets,
            received_packets: self.recvd_packets,
            retransmitted_packets: self.retrans_packets,
            rtt: self.rtt,
            rtt_var: self.rtt_var,
            sender_buffer: self.buffer.len() as u32 * self.settings.max_packet_size,
            snd: {
                let si = self.congest_ctrl.send_interval();

                si.subsec_nanos() as i32 / 1_000
            },
        }
    }

    fn make_cc_info(&self) -> CCData {
        CCData {
            est_bandwidth: self.est_link_cap,
            max_segment_size: self.settings.max_packet_size,
            latest_seq_num: Some(self.next_seq_number - 1),
            packet_arr_rate: self.pkt_arr_rate,
            rtt: Duration::from_micros(self.rtt as u64),
        }
    }

    fn handle_packet(&mut self, pack: Packet) -> Result<(), Error> {
        match pack {
            Packet::Control(ctrl) => {
                match ctrl.control_type {
                    ControlTypes::Ack {
                        ack_seq_num,
                        ack_number,
                        rtt,
                        rtt_variance,
                        packet_recv_rate,
                        est_link_cap,
                        ..
                    } => {
                        // if this ack number is less than or equal to
                        // the largest received ack number, than discard it
                        // this can happen thorough packet reordering OR losing an ACK2 packet
                        if ack_number <= self.lr_acked_packet {
                            return Ok(());
                        }

                        // update the packets received count
                        self.recvd_packets += ack_number - self.lr_acked_packet;

                        // 1) Update the largest acknowledged sequence number, which is the ACK number
                        self.lr_acked_packet = ack_number;

                        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
                        trace!("Sending ACK2 for {}", ack_seq_num);
                        let now = self.get_timestamp();
                        self.sock.start_send((
                            Packet::Control(ControlPacket {
                                timestamp: now,
                                dest_sockid: self.settings.remote_sockid,
                                control_type: ControlTypes::Ack2(ack_seq_num),
                            }),
                            self.settings.remote,
                        ))?;

                        // 3) Update RTT and RTTVar.
                        self.rtt = rtt.unwrap_or(0);
                        self.rtt_var = rtt_variance.unwrap_or(0);

                        // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                        // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

                        // 5) Update flow window size.
                        {
                            let cc_info = self.make_cc_info();
                            self.congest_ctrl.on_ack(&cc_info);
                        }

                        // 6) If this is a Light ACK, stop.
                        // TODO: wat

                        // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
                        //    value carried in the ACK.
                        self.pkt_arr_rate =
                            self.pkt_arr_rate / 8 * 7 + packet_recv_rate.unwrap_or(0) / 8;

                        // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
                        //    the value carried in the ACK.
                        self.est_link_cap = (self.est_link_cap * 7 + est_link_cap.unwrap_or(0)) / 8;

                        // 9) Update sender's buffer (by releasing the buffer that has been
                        //    acknowledged).
                        while ack_number > self.first_seq {
                            self.buffer.pop_front();
                            self.first_seq += 1;
                        }

                        // 10) Update sender's loss list (by removing all those that has been
                        //     acknowledged).
                        // TODO: this isn't the most effiecnet algorithm, it checks the beginning of the array many times
                        while let Some(id) = self
                            .loss_list
                            .iter()
                            .position(|x| ack_number > x.seq_number)
                        {
                            self.loss_list.remove(id);

                            // this means a packet was lost then retransmitted
                            self.retrans_packets += 1;
                        }
                    }
                    ControlTypes::Ack2(_) => warn!("Sender received ACK2, unusual"),
                    ControlTypes::DropRequest { .. } => unimplemented!(),
                    ControlTypes::Handshake(_shake) => unimplemented!(),
                    // TODO: reset EXP-ish
                    ControlTypes::KeepAlive => {}
                    ControlTypes::Nak(info) => {
                        // 1) Add all sequence numbers carried in the NAK into the sender's loss list.
                        // 2) Update the SND period by rate control (see section 3.6).
                        // 3) Reset the EXP time variable.

                        for lost in decompress_loss_list(info.iter().cloned()) {
                            // TODO: this prob doens't need to be a find
                            let packet = match self
                                .buffer
                                .iter()
                                .find(|pack| pack.seq_number == lost)
                            {
                                Some(p) => p,
                                None => {
                                    warn!("NAK received for packet {} that's not in the buffer, maybe it's already been ACKed", lost);
                                    continue;
                                }
                            };

                            self.loss_list.push_back(packet.clone());
                        }

                        // update CC
                        if !self.loss_list.is_empty() {
                            let cc_info = self.make_cc_info();
                            self.congest_ctrl
                                .on_nak(self.loss_list.back().unwrap().seq_number, &cc_info);
                        }

                        trace!(
                            "Loss list={:?}",
                            self.loss_list
                                .iter()
                                .map(|ll| ll.seq_number)
                                .collect::<Vec<_>>()
                        );

                        // TODO: reset EXP
                    }
                    ControlTypes::Shutdown => unimplemented!(),
                    ControlTypes::Custom {
                        custom_type,
                        ref control_info,
                    } => {
                        // decode srt packet
                        let srt_packet =
                            SrtControlPacket::parse(custom_type, &mut Cursor::new(control_info))?;

                        self.handle_srt_control_packet(srt_packet)?;
                    }
                }
            }
            Packet::Data { .. } => warn!("Sender received data packet"),
        }

        Ok(())
    }

    fn handle_srt_control_packet(&mut self, pack: SrtControlPacket) -> Result<(), Error> {
        match pack {
            SrtControlPacket::HandshakeRequest(_) => warn!("Sender received SRT handshake request"),
            SrtControlPacket::HandshakeResponse(shake) => {
                // make sure the SRT version matches ours
                if srt_version::CURRENT != shake.version {
                    bail!(
                        "Incomatible version, local is {}, remote is {}",
                        srt_version::CURRENT,
                        shake.version
                    );
                }

                // make sure the other side is a receiver
                if shake.flags.contains(SrtShakeFlags::TSBPDSND) {
                    bail!("Sender received SRT handshake from another sender");
                }

                // make sure the recvr flag is set, otherwise nothing is set
                if !shake.flags.contains(SrtShakeFlags::TSBPDRCV) {
                    bail!("Sender received SRT handshake with neither sender or receiver bits set");
                }

                // all setup, using TSBPD from the shake
                info!("Got SRT handshake packet, using tsbpd={:?}", shake.latency);
            }
        }

        Ok(())
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

    fn get_next_payload(&mut self) -> Option<Packet> {
        let (payload, is_msg_end, is_msg_begin) = {
            let payload = match self.pending_packets.pop_front() {
                Some(p) => p,
                // All packets have been flushed
                None => return None,
            };

            // cache this so we don't overwrite it
            let is_msg_begin = self.at_msg_beginning;

            // if we need to break this packet up
            if payload.len() > self.settings.max_packet_size as usize {
                // re-add the rest of the packet
                self.pending_packets.push_front(
                    payload.slice(self.settings.max_packet_size as usize, payload.len()),
                );
                self.at_msg_beginning = false;

                (
                    payload.slice(0, self.settings.max_packet_size as usize),
                    false,
                    is_msg_begin,
                )
            } else {
                self.at_msg_beginning = true;
                (payload, true, is_msg_begin)
            }
        };

        let pack = DataPacket {
            dest_sockid: self.settings.remote_sockid,
            in_order_delivery: false, // TODO: research this
            message_loc: if is_msg_begin {
                PacketLocation::FIRST
            } else {
                PacketLocation::empty()
            } | if is_msg_end {
                PacketLocation::LAST
            } else {
                PacketLocation::empty()
            },

            // if this marks the beginning of the next message, get a new message number, else don't
            message_number: if is_msg_begin {
                self.get_new_message_number()
            } else {
                self.next_message_number - 1
            },
            seq_number: self.get_new_sequence_number(),
            timestamp: self.get_timestamp(),
            payload,
        };

        // add it to the buffer
        self.buffer.push_back(pack.clone());

        Some(Packet::Data(pack))
    }

    fn send_srt_handshake(&mut self) -> Result<(), Error> {
        debug!("Sending SRT handshake packet");

        // make SRT handshake packet
        let mut bytes = BytesMut::new();
        let custom_type = SrtControlPacket::HandshakeRequest(SrtHandshake {
            version: srt_version::CURRENT,
            flags: SrtShakeFlags::TSBPDSND, // TODO: the reference implementation sets a lot more of these, research
            latency: self
                .settings
                .tsbpd_latency
                .unwrap_or(Duration::from_millis(120)),
        }).serialize(&mut bytes);

        let now = self.get_timestamp();
        self.sock.start_send((
            Packet::Control(ControlPacket {
                timestamp: now,
                dest_sockid: self.settings.remote_sockid,
                control_type: ControlTypes::Custom {
                    custom_type,
                    control_info: bytes.freeze(),
                },
            }),
            self.settings.remote,
        ))?;

        Ok(())
    }

    fn get_timestamp(&self) -> i32 {
        self.settings.get_timestamp()
    }
}

impl<T, CC> Sink for Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestCtrl,
{
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {
        assert!(!self.closed, "`start_send` called after sender close");

        self.pending_packets.push_back(item);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        // we need to poll_complete this until completion
        // this poll_complete could have come from a wakeup of that, so call it
        if let Async::Ready(_) = self.sock.poll_complete()? {
            // if everything is flushed, return Ok
            if self.loss_list.is_empty()
                && self.pending_packets.is_empty()
                && self.lr_acked_packet == self.next_seq_number
                && self.buffer.is_empty()
            {
                // TODO: this is wrong for KeepAlive
                debug!("Returning ready");
                return Ok(Async::Ready(()));
            }
        }

        if self.srt_handshake_interval.is_some() {
            if let Async::Ready(_) = self.srt_handshake_interval.as_mut().unwrap().poll()? {
                self.send_srt_handshake()?;
                self.sock.poll_complete()?;
            }
        }

        loop {
            // do we have any packets to handle?
            while let Async::Ready(a) = self.sock.poll()? {
                match a {
                    Some((pack, addr)) => {
                        debug!("Got packet: {:?}", pack);
                        // ignore the packet if it isn't from the right address
                        if addr == self.settings.remote {
                            self.handle_packet(pack)?;
                        }
                    }
                    // stream has ended, this is weird
                    None => {
                        bail!("Unexpected EOF of underlying stream");
                    }
                }
            }
            // if we're here, we are guaranteed to have a NotReady, so returning NotReady is OK

            // wait for the SND timer to timeout
            try_ready!(self.snd_timer.poll());

            // 6) Wait (SND - t) time, where SND is the inter-packet interval
            //     updated by congestion control and t is the total time used by step
            //     1 to step 5. Go to 1).
            {
                let cc_info = self.make_cc_info();
                self.congest_ctrl.on_packet_sent(&cc_info);
            }

            // reset the timer
            self.snd_timer.reset(self.congest_ctrl.send_interval());

            // 1) If the sender's loss list is not empty, send all the packets it in
            if let Some(pack) = self.loss_list.pop_front() {
                debug!("Sending packet in loss list, seq={:?}", pack.seq_number);
                self.sock
                    .start_send((Packet::Data(pack), self.settings.remote))?;
            } else {
                // 2) In messaging mode, if the packets has been the loss list for a
                //    time more than the application specified TTL (time-to-live), send
                //    a message drop request and remove all related packets from the
                //    loss list. Go to 1).

                // TODO: I honestly don't know what this means

                // 3) Wait until there is application data to be sent.

                // a. If the number of unacknowledged packets exceeds the
                //    flow/congestion window size, wait until an ACK comes. Go to
                //    1).
                // TODO: account for looping here
                if self.lr_acked_packet < self.next_seq_number - self.congest_ctrl.window_size() {
                    // flow window exceeded, wait for ACK
                    trace!("Flow window exceeded lr_acked={:?}, next_seq={:?}, window_size={}, next_seq-window={:?}", 
                        self.lr_acked_packet,
                        self.next_seq_number,
                        self.congest_ctrl.window_size(),
                        self.next_seq_number - self.congest_ctrl.window_size());

                    continue;
                }

                // b. Pack a new data packet and send it out.
                {
                    let payload = match self.get_next_payload() {
                        Some(p) => p,
                        // All packets have been flushed
                        None => continue,
                    };
                    debug!(
                        "Sending packet: {}; pending.len={}; SND={:?}",
                        self.next_seq_number - 1,
                        self.pending_packets.len(),
                        self.congest_ctrl.send_interval(),
                    );
                    self.sock.start_send((payload, self.settings.remote))?;
                }

                // 5) If the sequence number of the current packet is 16n, where n is an
                //     integer, go to 2) (which is send another packet).
                if (self.next_seq_number - 1) % 16 == 0 {
                    let payload = match self.get_next_payload() {
                        Some(p) => p,
                        // All packets have been flushed
                        None => continue,
                    };
                    self.sock.start_send((payload, self.settings.remote))?;
                }
            }
            self.sock.poll_complete()?;
        }
    }

    fn close(&mut self) -> Poll<(), Error> {
        try_ready!(self.poll_complete());

        if !self.closed {
            // once it's all flushed, send a single Shutdown packet
            info!("Sending shutdown");
            let ts = self.get_timestamp();
            self.sock.start_send((
                Packet::Control(ControlPacket {
                    dest_sockid: self.settings.remote_sockid,
                    timestamp: ts,
                    control_type: ControlTypes::Shutdown,
                }),
                self.settings.remote,
            ))?;

            // cancel the handshake timer
            self.srt_handshake_interval = None;
        }

        self.closed = true;

        self.sock.poll_complete()
    }
}

// Stats streaming
impl<T, CC> Stream for Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestCtrl,
{
    type Item = Stats;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Stats>, Error> {
        try_ready!(self.stats_interval.poll());

        Ok(Async::Ready(Some(self.stats())))
    }
}
