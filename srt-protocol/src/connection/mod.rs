pub mod status;
pub use status::*;

use std::{
    convert::TryFrom,
    fmt::Debug,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::{
    options::*,
    packet::*,
    protocol::{
        handshake::Handshake,
        output::Output,
        receiver::{Receiver, ReceiverContext},
        sender::{Sender, SenderContext},
        time::Timers,
    },
    settings::CipherSettings,
    statistics::SocketStatistics,
};

#[derive(Debug, Eq, PartialEq)]
pub struct Connection {
    pub settings: ConnectionSettings,
    pub handshake: Handshake,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ConnectionSettings {
    /// The remote socket to send & receive to
    pub remote: SocketAddr,

    /// The socket id of the UDT entity on the other side
    pub remote_sockid: SocketId,

    /// The local UDT socket id
    pub local_sockid: SocketId,

    /// The time that this socket started at, used to develop timestamps
    /// This is precisely the time that the Initiator sends the first packet (or an approximation if not the initiator, assuming symmetrical latency)
    pub socket_start_time: Instant,

    /// the initial RTT, to be used with TSBPD
    pub rtt: Duration,

    /// The first sequence number that will be sent/received
    pub init_seq_num: SeqNumber,

    /// The maximum packet size
    pub max_packet_size: ByteCount,

    /// The maxiumum flow size
    pub max_flow_size: PacketCount,

    /// The TSBPD of the connection--the max of each side's repspective latencies
    pub send_tsbpd_latency: Duration,
    pub recv_tsbpd_latency: Duration,

    /// Size of the receive buffer, in packets
    pub recv_buffer_size: PacketCount,
    pub cipher: Option<CipherSettings>,
    pub stream_id: Option<String>,
    pub bandwidth: LiveBandwidthMode,
    pub statistics_interval: Duration,
}

#[derive(Debug)]
pub struct DuplexConnection {
    settings: ConnectionSettings,
    timers: Timers,
    handshake: Handshake,
    output: Output,
    sender: Sender,
    receiver: Receiver,
    stats: SocketStatistics,
    status: ConnectionStatus,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action<'a> {
    ReleaseData((Instant, Bytes)),
    SendPacket((Packet, SocketAddr)),
    UpdateStatistics(&'a SocketStatistics),
    WaitForData(Duration),
    Close,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Input {
    Data(Option<(Instant, Bytes)>),
    Packet(ReceivePacketResult),
    DataReleased,
    PacketSent,
    StatisticsUpdated,
    Timer,
}

impl DuplexConnection {
    pub fn new(connection: Connection) -> DuplexConnection {
        let settings = connection.settings;
        DuplexConnection {
            settings: settings.clone(),
            handshake: connection.handshake,
            output: Output::new(&settings),
            status: ConnectionStatus::new(settings.send_tsbpd_latency),
            timers: Timers::new(settings.socket_start_time, settings.statistics_interval),
            stats: SocketStatistics::new(),
            receiver: Receiver::new(settings.clone()),
            sender: Sender::new(settings),
        }
    }

    pub fn handle_input(&mut self, now: Instant, input: Input) -> Action {
        self.debug(now, "input", &input);

        match input {
            Input::Data(data) => self.handle_data_input(now, data),
            Input::Packet(packet) => self.handle_packet_input(now, packet),
            _ => {}
        };

        let action = if self.should_close(now) {
            Action::Close
        } else if self.should_update_statistics(now) {
            self.update_statistics(now);
            Action::UpdateStatistics(&self.stats)
        } else if let Some(packet) = self.next_packet(now) {
            Action::SendPacket(packet)
        } else if let Some(data) = self.next_data(now) {
            Action::ReleaseData(data)
        } else {
            Action::WaitForData(self.next_timer(now) - now)
        };

        self.debug(now, "action", &action);
        action
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn update_statistics(&mut self, now: Instant) {
        self.stats.elapsed_time = now - self.settings.socket_start_time;
        self.stats.tx_buffered_time = self.sender.tx_buffered_time();
        self.stats.tx_buffered_data = self.sender.tx_buffered_packets();
        self.stats.tx_buffered_bytes = self.sender.tx_buffered_bytes();

        self.stats.rx_acknowledged_time = self.receiver.rx_acknowledged_time();
    }

    pub fn next_packet(&mut self, now: Instant) -> Option<(Packet, SocketAddr)> {
        self.output.pop_packet().map(|p| {
            self.timers.reset_keepalive(now);
            self.stats.tx_all_packets += 1;
            self.stats.tx_all_bytes += u64::try_from(p.wire_size()).unwrap();

            // payload length + (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT)
            match &p {
                Packet::Data(d) => {
                    self.stats.tx_data += 1;
                    self.stats.tx_bytes += d.payload.len() as u64 + DataPacket::HEADER_SIZE;
                }
                Packet::Control(c) => match c.control_type {
                    ControlTypes::Ack(ref a) => {
                        self.stats.tx_ack += 1;
                        if matches!(a, Acknowledgement::Lite(_)) {
                            self.stats.tx_light_ack += 1;
                        }
                    }
                    ControlTypes::Nak(_) => {
                        self.stats.tx_nak += 1;
                    }
                    ControlTypes::Ack2(_) => {
                        self.stats.tx_ack2 += 1;
                    }
                    _ => {}
                },
            }
            self.debug(now, "send", &p);
            (p, self.settings.remote)
        })
    }

    pub fn next_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        match self.receiver.arq.pop_next_message(now) {
            Ok(Some(data)) => {
                self.debug(now, "output", &data);
                Some(data)
            }
            Err(error) => {
                self.warn(now, "output", &error);
                let dropped = error.too_late_packets.end - error.too_late_packets.start;
                self.stats.rx_dropped_data += dropped as u64;
                None
            }
            _ => None,
        }
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        let has_packets_to_send = self.sender.has_packets_to_send();
        let next_message = self.receiver.arq.next_message_release_time();
        let unacked_packets = self.receiver.arq.unacked_packet_count();
        self.timers
            .next_timer(now, has_packets_to_send, next_message, unacked_packets)
    }

    pub fn should_close(&mut self, now: Instant) -> bool {
        if !self.is_open() {
            true
        } else {
            self.check_timers(now);
            false
        }
    }

    pub fn should_update_statistics(&mut self, now: Instant) -> bool {
        self.timers.check_statistics(now).is_some()
    }

    pub fn statistics(&self) -> &SocketStatistics {
        &self.stats
    }

    pub fn check_timers(&mut self, now: Instant) -> Instant {
        if self.timers.check_full_ack(now).is_some() {
            self.receiver().on_full_ack_event(now);
        }
        if self.timers.check_nak(now).is_some() {
            self.receiver().on_nak_event(now);
        }
        if self.timers.check_peer_idle_timeout(now).is_some() {
            self.on_peer_idle_timeout(now);
        }
        if let Some(elapsed_periods) = self.timers.check_snd(now) {
            self.sender().on_snd_event(now, elapsed_periods)
        }
        if self.timers.check_keepalive(now).is_some() {
            self.output.send_control(now, ControlTypes::KeepAlive);
        }

        if self
            .status
            .check_receive_close_timeout(now, self.receiver.is_flushed())
        {
            self.receiver().on_close_timeout(now);
        }
        if self.status.check_sender_shutdown(
            now,
            self.sender.is_flushed(),
            self.receiver.is_flushed(),
            self.output.is_empty(),
        ) {
            self.output.send_control(now, ControlTypes::Shutdown);
        }

        self.next_timer(now)
    }

    pub fn handle_data_input(&mut self, now: Instant, data: Option<(Instant, Bytes)>) {
        self.debug(now, "input", &data);
        match data {
            Some(item) => {
                self.sender().handle_data(now, item);
            }
            None => {
                self.handle_data_stream_close(now);
            }
        }
    }

    pub fn handle_packet_input(&mut self, now: Instant, packet: ReceivePacketResult) {
        self.debug(now, "packet", &packet);
        use ReceivePacketError::*;
        match packet {
            Ok(packet) => self.handle_packet(now, packet),
            Err(Io(error)) => self.handle_socket_close(now, error),
            Err(Parse(e)) => self.warn(now, "packet", &e),
        }
    }

    fn handle_data_stream_close(&mut self, now: Instant) {
        self.debug(now, "closed data", &());
        self.status.on_data_stream_closed(now);
    }

    fn handle_socket_close(&mut self, now: Instant, error: io::Error) {
        self.warn(now, "closed socket", &error);
        self.status.on_socket_closed(now);
    }

    pub fn on_peer_idle_timeout(&mut self, now: Instant) {
        self.output.send_control(now, ControlTypes::Shutdown);
        self.status.on_peer_idle_timeout(now);
    }

    fn handle_packet(&mut self, now: Instant, (packet, from): (Packet, SocketAddr)) {
        // TODO: record/report packets from invalid hosts?
        // We don't care about packets from elsewhere
        if from != self.settings.remote {
            self.info(now, "invalid address", &(packet, from));
            return;
        }

        if self.settings.local_sockid != packet.dest_sockid() {
            self.info(now, "invalid socket id", &(packet, from));
            return;
        }

        self.timers.reset_exp(now);

        self.stats.rx_all_packets += 1;
        self.stats.rx_all_bytes += u64::try_from(packet.wire_size()).unwrap();
        match packet {
            Packet::Data(data) => self.receiver().handle_data_packet(now, data),
            Packet::Control(control) => self.handle_control_packet(now, control),
        }
    }

    fn handle_control_packet(&mut self, now: Instant, control: ControlPacket) {
        self.receiver().synchronize_clock(now, control.timestamp);

        use ControlTypes::*;
        match control.control_type {
            // sender-responsible packets
            Ack(ack) => self.sender().handle_ack_packet(now, ack),
            DropRequest { range, .. } => self.receiver().handle_drop_request(now, range),
            Handshake(shake) => self.handle_handshake_packet(now, shake),
            Nak(nak) => self.sender().handle_nak_packet(now, nak),
            // receiver-responsible
            Ack2(seq_num) => self.receiver().handle_ack2_packet(now, seq_num),
            // both
            Shutdown => self.status.handle_shutdown_packet(now),
            // neither--this exists just to keep the connection alive
            KeepAlive => {}
            // TODO: case UMSG_CGWARNING: // 100 - Delay Warning
            //            // One way packet delay is increasing, so decrease the sending rate
            //            ControlTypes::DelayWarning?
            CongestionWarning => todo!(),
            // TODO: case UMSG_PEERERROR: // 1000 - An error has happened to the peer side
            PeerError(_) => todo!(),
            // TODO: case UMSG_EXT: // 0x7FFF - reserved and user defined messages
            Srt(s) => self.handle_srt_control_packet(now, s),
        }
    }

    fn handle_handshake_packet(&mut self, now: Instant, handshake: HandshakeControlInfo) {
        if let Some(control) = self.handshake.handle_handshake(handshake) {
            self.output.send_control(now, control);
        }
    }

    fn handle_srt_control_packet(&mut self, now: Instant, pack: SrtControlPacket) {
        use self::SrtControlPacket::*;
        match pack {
            HandshakeRequest(_) | HandshakeResponse(_) => self.warn(now, "handshake", &pack),
            KeyRefreshRequest(keying_material) => self
                .receiver()
                .handle_key_refresh_request(now, keying_material),
            KeyRefreshResponse(keying_material) => {
                self.sender().handle_key_refresh_response(keying_material)
            }
            _ => unimplemented!("{:?}", pack),
        }
    }

    fn sender(&mut self) -> SenderContext {
        SenderContext::new(
            &mut self.status,
            &mut self.timers,
            &mut self.output,
            &mut self.stats,
            &mut self.sender,
        )
    }

    fn receiver(&mut self) -> ReceiverContext {
        ReceiverContext::new(
            &mut self.timers,
            &mut self.output,
            &mut self.stats,
            &mut self.receiver,
        )
    }

    fn debug(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::debug!(
            "{:?}|{:?}|{} - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            tag,
            debug
        );
    }

    fn info(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::info!(
            "{:?}|{:?}|{} - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            tag,
            debug
        );
    }

    fn warn(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::warn!(
            "{:?}|{:?}|{} - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            tag,
            debug
        );
    }
}

#[cfg(test)]
mod duplex_connection {
    use assert_matches::assert_matches;

    use Action::*;
    use ControlTypes::*;
    use Packet::*;

    use super::*;

    const MILLIS: Duration = Duration::from_millis(1);
    const SND: Duration = MILLIS;
    const TSBPD: Duration = Duration::from_secs(1);

    fn remote_addr() -> SocketAddr {
        ([127, 0, 0, 1], 2223).into()
    }

    fn remote_sockid() -> SocketId {
        SocketId(2)
    }

    fn local_sockid() -> SocketId {
        SocketId(2)
    }

    fn new_connection(now: Instant) -> Connection {
        Connection {
            settings: ConnectionSettings {
                remote: remote_addr(),
                remote_sockid: remote_sockid(),
                local_sockid: local_sockid(),
                socket_start_time: now,
                rtt: Duration::default(),
                init_seq_num: SeqNumber::new_truncate(0),
                max_packet_size: ByteCount(1316),
                max_flow_size: PacketCount(8192),
                send_tsbpd_latency: TSBPD,
                recv_tsbpd_latency: TSBPD,
                recv_buffer_size: PacketCount(1024),
                cipher: None,
                stream_id: None,
                bandwidth: LiveBandwidthMode::Unlimited,
                statistics_interval: Duration::from_secs(10),
            },
            handshake: crate::protocol::handshake::Handshake::Connector,
        }
    }

    #[test]
    fn input_data_close() {
        let start = Instant::now();
        let mut connection = DuplexConnection::new(new_connection(start));

        let mut now = start;
        assert_eq!(
            connection.handle_input(now, Input::Timer),
            WaitForData(102 * MILLIS)
        );
        assert_eq!(
            connection.handle_input(now, Input::Data(Some((start, Bytes::new())))),
            WaitForData(SND)
        );

        assert_eq!(
            connection.handle_input(now, Input::Data(None)),
            WaitForData(SND),
            "input data 'close' should drain the send buffers"
        );

        now += SND;
        assert_matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        );

        // acknowledgement
        now += SND;
        let packet = Control(ControlPacket {
            timestamp: TimeStamp::MIN,
            dest_sockid: SocketId(2),
            control_type: Ack(Acknowledgement::Full(
                SeqNumber(1),
                AckStatistics {
                    rtt: TimeSpan::ZERO,
                    rtt_variance: TimeSpan::ZERO,
                    buffer_available: 10000,
                    packet_receive_rate: None,
                    estimated_link_capacity: None,
                    data_receive_rate: None,
                },
                FullAckSeqNumber::INITIAL,
            )),
        });
        assert_eq!(
            connection.handle_input(now, Input::Packet(Ok((packet, remote_addr())))),
            SendPacket((
                Control(ControlPacket {
                    timestamp: TimeStamp::from_micros(2_000),
                    dest_sockid: SocketId(2),
                    control_type: Ack2(FullAckSeqNumber::INITIAL),
                }),
                remote_addr()
            ))
        );

        // closing: drain last item in send buffer
        assert_matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        );
        assert_matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((
                Control(ControlPacket {
                    control_type: Shutdown,
                    ..
                }),
                _
            ))
        );
        assert_eq!(
            connection.handle_input(now, Input::Timer),
            WaitForData(100 * MILLIS)
        );
        assert_eq!(connection.handle_input(now, Input::Timer), Close);
    }

    #[test]
    fn too_late_packet_drop() {
        let start = Instant::now();
        let mut connection = DuplexConnection::new(new_connection(start));

        let mut now = start;
        assert_eq!(
            connection.handle_input(now, Input::Timer),
            WaitForData(102 * MILLIS)
        );
        assert_eq!(
            connection.handle_input(now, Input::Data(Some((start, Bytes::new())))),
            WaitForData(SND)
        );
        // the last packet sent is kept around for retransmit on flush
        // keeping this original behavior intact otherwise integration tests fail
        assert_eq!(
            connection.handle_input(now, Input::Data(Some((start, Bytes::new())))),
            WaitForData(SND)
        );

        now += SND;
        assert_matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        );

        assert_matches!(
            connection.handle_input(now + TSBPD, Input::Timer),
            SendPacket((Data(_), _))
        );

        // timeout
        now += TSBPD + TSBPD / 4; // TSBPD * 1.25
        assert_matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((
                Control(ControlPacket {
                    control_type: KeepAlive,
                    ..
                }),
                _
            ))
        );
        assert_matches!(connection.handle_input(now, Input::Timer), WaitForData(_));

        // https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-3.2.9
        //
        // 3.2.9.  Message Drop Request
        //
        //    A Message Drop Request control packet is sent by the sender to the
        //    receiver when it requests the retransmission of an unacknowledged
        //    packet (all or part of a message) which is not present in the
        //    sender's buffer.  This may happen, for example, when a TTL parameter
        //    (passed in the sending function) triggers a timeout for
        //    retransmitting lost packets which constitute parts of a message,
        //    causing these packets to be removed from the sender's buffer.
        //
        //    The sender notifies the receiver that it must not wait for
        //    retransmission of this message.  Note that a Message Drop Request
        //    control packet is not sent if the Too Late Packet Drop mechanism
        //    (Section 4.6) causes the sender to drop a message, as in this case
        //    the receiver is expected to drop it anyway.
        assert_eq!(
            connection.handle_input(
                now,
                Input::Packet(Ok((
                    Control(ControlPacket {
                        timestamp: TimeStamp::MIN + SND + TSBPD + TSBPD / 4,
                        dest_sockid: remote_sockid(),
                        control_type: Nak((SeqNumber(0)..SeqNumber(2)).into()),
                    }),
                    remote_addr()
                )))
            ),
            SendPacket((
                Control(ControlPacket {
                    timestamp: TimeStamp::MIN + SND + TSBPD + TSBPD / 4,
                    dest_sockid: remote_sockid(),
                    control_type: DropRequest {
                        msg_to_drop: MsgNumber(0),
                        range: SeqNumber(0)..=SeqNumber(1)
                    }
                }),
                remote_addr()
            ))
        );
    }
}
