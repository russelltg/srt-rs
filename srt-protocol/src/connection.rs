use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::packet::{ControlTypes, SrtControlPacket};
use crate::protocol::handshake::Handshake;
use crate::protocol::receiver::Receiver;
use crate::protocol::sender::Sender;
use crate::protocol::TimeSpan;
use crate::{crypto::CryptoManager, ControlPacket, Packet, SeqNumber, SocketId};
use bytes::Bytes;
use log::{debug, info, warn};
use std::cmp::min;

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
    pub max_packet_size: u32,

    /// The maxiumum flow size
    pub max_flow_size: u32,

    /// The TSBPD of the connection--the max of each side's repspective latencies
    pub send_tsbpd_latency: Duration,
    pub recv_tsbpd_latency: Duration,

    // if this stream is encrypted, it needs a crypto manager
    pub crypto_manager: Option<CryptoManager>,

    pub stream_id: Option<String>,
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
        *self != ConnectionStatus::Closed
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

    pub(crate) fn should_drain(&self) -> bool {
        use ConnectionStatus::*;
        matches!(*self, Shutdown(_) | Drain(_))
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
            receiver: Receiver::new(settings.clone(), connection.handshake.clone()),
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
            Input::Data(Some(data)) => self.sender.handle_data(data, now),
            Input::Data(None) => self.handle_data_stream_close(now),
            Input::Packet(Some(packet)) => self.handle_packet(now, packet),
            Input::Packet(None) => self.handle_socket_close(),
            _ => {}
        };

        let action = if self.should_close(now) {
            Action::Close
        } else if let Some(data) = self.next_data(now) {
            Action::ReleaseData(data)
        } else if let Some(packet) = self.next_packet() {
            Action::SendPacket(packet)
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
        !(self.status == ConnectionStatus::Closed
            || (!self.sender.is_open() && self.receiver.is_flushed())
            || (!self.receiver.is_open() && self.sender.is_flushed()))
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        self.sender
            .next_packet()
            .or_else(|| self.receiver.next_packet())
    }

    pub fn next_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        self.receiver.next_data(now)
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
        let _status = &mut self.status;
        let sender = &mut self.sender;
        let receiver = &mut self.receiver;

        sender.check_timers(now);
        receiver.check_timers(now);

        // if status.check_shutdown(now, || sender.is_flushed()) {
        //     debug!("{:?} sending shutdown", self.settings.local_sockid);
        //     sender.send_shutdown(now);
        // }

        self.next_timer(now)
    }

    pub fn handle_data_input(&mut self, now: Instant, data: Option<(Instant, Bytes)>) {
        debug!(
            "{:?}|{:?}|data - {:?}",
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
            "{:?}|{:?}|pack - {:?}",
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
            Packet::Data(data) => self.receiver.handle_data_packet(data, now),
            Packet::Control(control) => self.handle_control_packet(now, control),
        }
    }

    fn handle_control_packet(&mut self, now: Instant, control: ControlPacket) {
        use ControlTypes::*;

        self.receiver.synchronize_clock(now, control.timestamp);
        match control.control_type {
            // sender-responsble packets
            Ack(info) => self.sender.handle_ack_packet(now, info),
            DropRequest { .. } => unimplemented!(),
            Handshake(shake) => self.sender.handle_handshake_packet(shake, now),
            Nak(nack) => self.sender.handle_nack_packet(nack),
            // receiver-respnsible
            Ack2(seq_num) => self.receiver.handle_ack2_packet(seq_num, now),
            // both
            Shutdown => {
                self.sender.handle_shutdown_packet(now);
                self.receiver.handle_shutdown_packet(now);
            }
            // neither--this exists just to keep the connection alive
            KeepAlive => {}
            Srt(s) => self.handle_srt_control_packet(s),
            // TODO: case UMSG_CGWARNING: // 100 - Delay Warning
            //            // One way packet delay is increasing, so decrease the sending rate
            //            ControlTypes::DelayWarning?

            // TODO: case UMSG_LOSSREPORT: // 011 - Loss Report is this Nak?
            // TODO: case UMSG_DROPREQ: // 111 - Msg drop request
            // TODO: case UMSG_PEERERROR: // 1000 - An error has happened to the peer side
            // TODO: case UMSG_EXT: // 0x7FFF - reserved and user defined messages
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

// TODO: revisit these unit tests once the desired DuplexConnection API is stabilized
#[cfg(test)]
mod duplex_connection {
    use super::*;

    const MILLIS: Duration = Duration::from_millis(1);
    const SND: Duration = MILLIS;
    const TSBPD: Duration = Duration::from_millis(20);

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
                crypto_manager: None,
                stream_id: None,
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
}
