use std::cmp::min;
use std::{
    net::SocketAddr,
    ops::Range,
    time::{Duration, Instant},
};

use crate::{
    crypto::CryptoManager,
    packet::{ControlTypes, SrtControlPacket},
    protocol::{handshake::Handshake, receiver::Receiver, sender::Sender, TimeSpan},
    ControlPacket, LiveBandwidthMode, Packet, SeqNumber, SocketId,
};
use bytes::Bytes;
use log::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct Connection {
    pub settings: ConnectionSettings,
    pub handshake: Handshake,
}

#[derive(Debug, Clone)]
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
    pub max_packet_size: usize,

    /// The maxiumum flow size
    pub max_flow_size: u32,

    /// The TSBPD of the connection--the max of each side's repspective latencies
    pub send_tsbpd_latency: Duration,
    pub recv_tsbpd_latency: Duration,

    /// Size of the receive buffer, in packets
    pub recv_buffer_size: usize,

    // if this stream is encrypted, it needs a crypto manager
    pub crypto_manager: Option<CryptoManager>,

    pub stream_id: Option<String>,
    pub bandwidth: LiveBandwidthMode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConnectionStatus {
    Open(Duration),
    Shutdown(Instant),
    Drain(Instant),
    Closed,
}

impl ConnectionStatus {
    pub fn is_open(&self) -> bool {
        matches!(*self, ConnectionStatus::Open(_))
    }

    pub fn is_closed(&self) -> bool {
        matches!(*self, ConnectionStatus::Closed)
    }

    pub fn should_drain(&self) -> bool {
        use ConnectionStatus::*;
        matches!(*self, Shutdown(_) | Drain(_))
    }

    pub fn shutdown(&mut self, now: Instant) {
        use ConnectionStatus::*;
        if let Open(timeout) = *self {
            *self = Shutdown(now + timeout);
        }
    }

    pub fn drain(&mut self, now: Instant) {
        use ConnectionStatus::*;
        if let Open(timeout) = *self {
            *self = Drain(now + timeout);
        }
    }

    pub fn check_shutdown<S: Fn() -> bool>(&mut self, now: Instant, is_flushed: S) -> bool {
        use ConnectionStatus::*;
        match *self {
            Shutdown(timeout) if is_flushed() || now > timeout => {
                *self = Drain(timeout);
                true
            }
            Drain(timeout) if is_flushed() || now > timeout => {
                *self = Closed;
                false
            }
            _ => false,
        }
    }

    pub fn check_close_timeout(&mut self, now: Instant, flushed: bool) -> bool {
        use ConnectionStatus::*;
        match *self {
            Shutdown(timeout) | Drain(timeout) if now > timeout => {
                *self = Closed;
                true
            }
            Shutdown(_) | Drain(_) if flushed => {
                *self = Closed;
                false
            }
            _ => false,
        }
    }
}

pub struct DuplexConnection {
    settings: ConnectionSettings,
    sender: Sender,
    receiver: Receiver,
    status: ConnectionStatus,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action {
    ReleaseData((Instant, Bytes)),
    SendPacket((Packet, SocketAddr)),
    WaitForData(Duration),
    Close,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Input {
    Data(Option<(Instant, Bytes)>),
    Packet(Option<(Packet, SocketAddr)>),
    DataReleased,
    PacketSent,
    Timer,
}

impl DuplexConnection {
    pub fn new(connection: Connection) -> DuplexConnection {
        let settings = connection.settings;
        DuplexConnection {
            status: ConnectionStatus::Open(settings.send_tsbpd_latency),
            settings: settings.clone(),
            receiver: Receiver::new(settings.clone()),
            sender: Sender::new(settings, connection.handshake),
        }
    }

    pub fn handle_input(&mut self, now: Instant, input: Input) -> Action {
        debug!(
            "{:?}|{:?}|input - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            input
        );

        match input {
            Input::Data(data) => self.handle_data_input(now, data),
            Input::Packet(packet) => self.handle_packet_input(now, packet),
            _ => {}
        };

        let action = if self.should_close(now) {
            Action::Close
        } else if let Some(packet) = self.next_packet(now) {
            Action::SendPacket(packet)
        } else if let Some(data) = self.next_data(now) {
            Action::ReleaseData(data)
        } else {
            Action::WaitForData(self.next_timer(now) - now)
        };

        debug!(
            "{:?}|{:?}|action - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            action
        );

        action
    }

    pub fn is_open(&self) -> bool {
        !(self.status.is_closed()
            || (self.sender.is_closed() && self.receiver.is_flushed())
            || self.receiver.is_closed())
    }

    pub fn next_packet(&mut self, now: Instant) -> Option<(Packet, SocketAddr)> {
        let packet = self.sender.next_packet().or_else(|| {
            self.receiver.next_packet().map(|p| {
                self.sender.reset_keep_alive(now);
                p
            })
        });
        if let Some(p) = &packet {
            debug!(
                "{:?}|{:?}|send - {:?}",
                TimeSpan::from_interval(self.settings.socket_start_time, now),
                self.settings.local_sockid,
                p
            );
        }
        packet
    }

    pub fn next_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        let data = self.receiver.next_data(now);
        if let Some(d) = &data {
            debug!(
                "{:?}|{:?}|output - {:?}",
                TimeSpan::from_interval(self.settings.socket_start_time, now),
                self.settings.local_sockid,
                d
            );
        }
        data
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        min(self.sender.next_timer(now), self.receiver.next_timer(now))
    }

    pub fn should_close(&mut self, now: Instant) -> bool {
        if !self.is_open() {
            true
        } else {
            self.check_timers(now);
            false
        }
    }

    pub fn check_timers(&mut self, now: Instant) -> Instant {
        let sender = &mut self.sender;
        let receiver = &mut self.receiver;

        receiver.check_timers(now);
        sender.check_timers(now);

        self.next_timer(now)
    }

    pub fn handle_data_input(&mut self, now: Instant, data: Option<(Instant, Bytes)>) {
        debug!(
            "{:?}|{:?}|input - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            data
        );
        match data {
            Some(item) => {
                self.sender.handle_data(item, now);
            }
            None => {
                self.handle_data_stream_close(now);
            }
        }
    }

    pub fn handle_packet_input(&mut self, now: Instant, packet: Option<(Packet, SocketAddr)>) {
        debug!(
            "{:?}|{:?}|packet - {:?}",
            TimeSpan::from_interval(self.settings.socket_start_time, now),
            self.settings.local_sockid,
            packet
        );
        match packet {
            Some(packet) => self.handle_packet(now, packet),
            None => self.handle_socket_close(),
        }
    }

    fn handle_data_stream_close(&mut self, now: Instant) {
        debug!("Incoming data stream closed");
        self.sender.handle_close(now);
    }

    fn handle_socket_close(&mut self) {
        info!(
            "{:?} Exiting because underlying stream ended",
            self.settings.local_sockid
        );
        self.status = ConnectionStatus::Closed;
    }

    fn handle_packet(&mut self, now: Instant, (packet, from): (Packet, SocketAddr)) {
        // TODO: record/report packets from invalid hosts?
        // We don't care about packets from elsewhere
        if from != self.settings.remote {
            info!("Packet received from unknown address: {:?}", from);
            return;
        }

        if self.settings.local_sockid != packet.dest_sockid() {
            // packet isn't applicable
            info!(
                "Packet send to socket id ({:?}) that does not match local ({:?})",
                packet.dest_sockid(),
                self.settings.local_sockid
            );
            return;
        }

        self.receiver.reset_exp(now);
        match packet {
            Packet::Data(data) => self.receiver.handle_data_packet(now, data),
            Packet::Control(control) => self.handle_control_packet(now, control),
        }
    }

    fn handle_control_packet(&mut self, now: Instant, control: ControlPacket) {
        use ControlTypes::*;

        self.receiver.synchronize_clock(now, control.timestamp);
        match control.control_type {
            // sender-responsble packets
            Ack(info) => self.sender.handle_ack_packet(now, info),
            DropRequest {
                start,
                end_inclusive,
                ..
            } => self.receiver.handle_drop_request(
                now,
                Range {
                    start,
                    end: end_inclusive + 1,
                },
            ),
            Handshake(shake) => self.sender.handle_handshake_packet(shake, now),
            Nak(nack) => self.sender.handle_nak_packet(now, nack),
            // receiver-respnsible
            Ack2(seq_num) => self.receiver.handle_ack2_packet(seq_num, now),
            // both
            Shutdown => {
                self.sender.handle_shutdown_packet(now);
                self.receiver.handle_shutdown_packet(now);
            }
            // neither--this exists just to keep the connection alive
            KeepAlive => {}
            // TODO: case UMSG_CGWARNING: // 100 - Delay Warning
            //            // One way packet delay is increasing, so decrease the sending rate
            //            ControlTypes::DelayWarning?
            CongestionWarning => todo!(),
            // TODO: case UMSG_PEERERROR: // 1000 - An error has happened to the peer side
            PeerError(_) => todo!(),
            // TODO: case UMSG_EXT: // 0x7FFF - reserved and user defined messages
            Srt(s) => self.handle_srt_control_packet(s),
        }
    }

    // handles a SRT control packet
    fn handle_srt_control_packet(&mut self, pack: SrtControlPacket) {
        use self::SrtControlPacket::*;
        match pack {
            HandshakeRequest(_) | HandshakeResponse(_) => {
                warn!("Received handshake SRT packet, HSv5 expected");
            }
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod duplex_connection {
    use super::*;
    use crate::packet::CompressedLossList;
    use crate::protocol::TimeStamp;
    use crate::seq_number::seq_num_range;
    use crate::{LiveBandwidthMode, MsgNumber};

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
                max_packet_size: 1316,
                max_flow_size: 8192,
                send_tsbpd_latency: TSBPD,
                recv_tsbpd_latency: TSBPD,
                recv_buffer_size: 1024 * 1316,
                crypto_manager: None,
                stream_id: None,
                bandwidth: LiveBandwidthMode::default(),
            },
            handshake: Handshake::Connector,
        }
    }

    #[test]
    fn input_data_close() {
        let start = Instant::now();
        let mut connection = DuplexConnection::new(new_connection(start));

        use crate::ControlPacket;
        use Action::*;
        use ControlTypes::*;
        use Packet::*;

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

        // drain
        now += SND;
        assert!(matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        ));
        assert_eq!(
            connection.handle_input(now, Input::Data(None)),
            WaitForData(101 * MILLIS)
        );

        // closing: drain last item in send buffer
        now += SND;
        assert!(matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        ));
        assert!(matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((
                Control(ControlPacket {
                    control_type: Shutdown,
                    ..
                }),
                _
            ))
        ));
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

        use crate::ControlPacket;
        use Action::*;
        use ControlTypes::*;
        use Packet::*;

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
        assert!(matches!(
            connection.handle_input(now, Input::Timer),
            SendPacket((Data(_), _))
        ));

        assert!(matches!(
            connection.handle_input(now + TSBPD, Input::Timer),
            SendPacket((Data(_), _))
        ));

        // timeout
        now += TSBPD + TSBPD / 4; // TSBPD * 1.25
        assert!(matches!(
            connection.handle_input(now, Input::Timer),
            WaitForData(_)
        ));

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
                Input::Packet(Some((
                    Control(ControlPacket {
                        timestamp: TimeStamp::MIN + SND + TSBPD + TSBPD / 4,
                        dest_sockid: remote_sockid(),
                        control_type: Nak(CompressedLossList::from_loss_list(seq_num_range(
                            SeqNumber(0),
                            SeqNumber(1),
                        ))),
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
                        start: SeqNumber(0),
                        end_inclusive: SeqNumber(0), // DropRequest has an inclusive range
                    }
                }),
                remote_addr()
            ))
        );
    }
}
