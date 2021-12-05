mod input;
mod session;
mod statistics;

use std::{collections::HashMap, fmt::Debug, net::SocketAddr, time::Duration, time::Instant};

use crate::{packet::*, protocol::time::Timer, settings::ConnInitSettings};

use session::*;

pub use crate::protocol::pending_connection::{AccessControlRequest, AccessControlResponse};
pub use input::*;
pub use statistics::*;

#[derive(Clone, Debug)]
pub struct ListenerSettings {}

#[derive(Debug)]
pub struct MultiplexListener {
    start_time: Instant,
    local_address: SocketAddr,
    settings: ConnInitSettings,
    sessions: HashMap<SessionId, SessionState>,
    stats: ListenerStatistics,
    stats_timer: Timer,
}

impl MultiplexListener {
    pub fn new(now: Instant, local_address: SocketAddr, settings: ConnInitSettings) -> Self {
        Self {
            start_time: now,
            local_address,
            settings,
            sessions: Default::default(),
            stats: Default::default(),
            stats_timer: Timer::new(now, Duration::from_secs(1)),
        }
    }

    pub fn handle_input<'s, 'a>(&'s mut self, now: Instant, input: Input) -> Action<'a>
    where
        'a: 's,
    {
        self.debug(now, "input", &input);

        let action = match input {
            Input::Packet(packet) => self.handle_input_packet(now, packet),
            Input::AccessResponse(response) => self.handle_input_access_response(now, response),
            Input::Timer => self.handle_timer(now),
            Input::Success(result_of) => self.handle_success(now, result_of),
            Input::Failure(result_of) => self.handle_failure(now, result_of),
        };

        self.debug(now, "action", &action);

        action
    }

    fn handle_input_packet<'s, 'a>(
        &'s mut self,
        now: Instant,
        packet: ReceivePacketResult,
    ) -> Action<'a>
    where
        'a: 's,
    {
        match packet {
            Ok(packet) => self.handle_packet(now, packet),
            Err(error) => self.handle_packet_receive_error(now, error),
        }
    }

    fn handle_input_access_response<'s, 'a>(
        &'s mut self,
        now: Instant,
        response: Option<(SessionId, AccessControlResponse)>,
    ) -> Action<'a>
    where
        'a: 's,
    {
        match response {
            Some((session_id, response)) => {
                self.handle_access_control_response(now, session_id, response)
            }
            None => self.handle_close(),
        }
    }

    fn handle_packet<'s, 'a>(&'s mut self, now: Instant, packet: (Packet, SocketAddr)) -> Action<'a>
    where
        'a: 's,
    {
        self.stats.rx_packets += 1;
        //self.stats.rx_bytes += packet
        let session_id = SessionId(packet.1, packet.0.dest_sockid());
        let session = match self.sessions.get_mut(&session_id) {
            Some(session) => session,
            None => {
                let session = SessionState::new_oending(self.settings.clone());
                self.sessions.insert(session_id, session);
                self.sessions.get_mut(&session_id).unwrap()
            }
        };
        session.handle_packet(now, session_id, packet)
    }

    fn handle_packet_receive_error<'s, 'a>(
        &'s mut self,
        now: Instant,
        error: ReceivePacketError,
    ) -> Action<'a>
    where
        'a: 's,
    {
        self.warn(now, "packet", &error);

        use ReceivePacketError::*;
        match error {
            Parse(_) => self.stats.rx_parse_errors += 1,
            Io(_) => self.stats.rx_io_errors += 1,
        }

        Action::WaitForInput
    }

    fn handle_access_control_response<'s, 'a>(
        &'s mut self,
        now: Instant,
        session_id: SessionId,
        response: AccessControlResponse,
    ) -> Action<'a>
    where
        'a: 's,
    {
        match self.sessions.get_mut(&session_id) {
            Some(session) => session.handle_access_control_response(now, session_id, response),
            None => Action::DropConnection(session_id),
        }
    }

    fn handle_timer<'s, 'a>(&'s mut self, _now: Instant) -> Action<'a>
    where
        'a: 's,
    {
        // TODO: create an action that returns an action with an Iterator that ticks time forward
        //  for all the sessions, yielding the results to the I/O loop
        Action::WaitForInput
    }

    fn handle_success<'s, 'a>(&'s mut self, _now: Instant, result_of: ResultOf) -> Action<'a>
    where
        'a: 's,
    {
        use ResultOf::*;
        match result_of {
            SendPacket(_) => {
                self.stats.tx_packets += 1;
            }
            RequestAccess(_) => {
                self.stats.cx_inbound += 1;
            }
            RejectConnection(session_id) => {
                self.stats.cx_rejected += 1;
                self.sessions.remove(&session_id);
            }
            OpenConnection(_) => {
                self.stats.cx_opened += 1;
            }
            DelegatePacket(_) => {
                self.stats.delegated_packets += 1;
            }
            DropConnection(session_id) => {
                self.stats.cx_dropped += 1;
                self.sessions.remove(&session_id);
            }
            UpdateStatistics => {}
        }
        Action::WaitForInput
    }

    fn handle_failure<'s, 'a>(&'s self, now: Instant, result_of: ResultOf) -> Action<'a>
    where
        'a: 's,
    {
        self.warn(now, "failure", &result_of);

        // TODO: stats? anything else?

        Action::WaitForInput
    }

    fn handle_close<'s, 'a>(&'s mut self) -> Action<'a>
    where
        'a: 's,
    {
        Action::Close
    }

    fn debug(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::debug!(
            "{:?}|listen:{}|{} - {:?}",
            TimeSpan::from_interval(self.start_time, now),
            self.local_address.port(),
            tag,
            debug
        );
    }

    fn warn(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::warn!(
            "{:?}|listen:{}|{} - {:?}",
            TimeSpan::from_interval(self.start_time, now),
            self.local_address.port(),
            tag,
            debug
        );
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use rand::random;

    use crate::options::SrtVersion;

    use super::*;

    fn conn_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8765)
    }

    fn test_induction() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: 1316,
            max_flow_size: 256_000,
            shake_type: ShakeType::Induction,
            socket_id: SocketId(15),
            syn_cookie: 0,
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info::default()),
        }
    }

    fn test_conclusion() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: 1316,
            max_flow_size: 256_000,
            shake_type: ShakeType::Conclusion,
            socket_id: SocketId(15),
            syn_cookie: crate::protocol::pending_connection::cookie::gen_cookie(&conn_addr()),
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info {
                crypto_size: 0,
                ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                    version: SrtVersion::CURRENT,
                    flags: SrtShakeFlags::SUPPORTED,
                    send_latency: Duration::from_secs(1),
                    recv_latency: Duration::from_secs(2),
                })),
                ext_km: None,
                ext_group: None,
                sid: None,
            }),
        }
    }

    fn dest_sock_id() -> SocketId {
        SocketId(6)
    }

    fn session_id() -> SessionId {
        SessionId(conn_addr(), dest_sock_id())
    }

    fn build_hs_pack(i: HandshakeControlInfo) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: dest_sock_id(),
            control_type: ControlTypes::Handshake(i),
        })
    }

    #[test]
    fn connect() {
        let settings = ConnInitSettings::default();
        let local = "0.0.0.0:2000".parse().unwrap();
        let mut listener = MultiplexListener::new(Instant::now(), local, settings);

        let packet = build_hs_pack(test_induction());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(matches!(action, Action::SendPacket(_)), "{:?}", action);

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(
            matches!(action, Action::RequestAccess(_, _)),
            "{:?}",
            action
        );

        let action = listener.handle_input(
            Instant::now(),
            Input::AccessResponse(Some((session_id(), AccessControlResponse::Accepted(None)))),
        );
        assert!(
            matches!(action, Action::OpenConnection(_, _)),
            "{:?}",
            action
        );

        use crate::listener::ResultOf::*;

        let action =
            listener.handle_input(Instant::now(), Input::Success(OpenConnection(session_id())));
        assert!(matches!(action, Action::WaitForInput), "{:?}", action);

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(
            matches!(action, Action::DelegatePacket(_, _)),
            "{:?}",
            action
        );
    }

    #[test]
    fn reject() {
        let settings = ConnInitSettings::default();
        let local = "127.0.0.1:2000".parse().unwrap();
        let mut listener = MultiplexListener::new(Instant::now(), local, settings);

        let packet = build_hs_pack(test_induction());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(matches!(action, Action::SendPacket(_)), "{:?}", action);

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(
            matches!(action, Action::RequestAccess(_, _)),
            "{:?}",
            action
        );

        let action = listener.handle_input(
            Instant::now(),
            Input::AccessResponse(Some((
                session_id(),
                AccessControlResponse::Rejected(RejectReason::User(100)),
            ))),
        );
        assert!(
            matches!(
                action,
                Action::RejectConnection(_, Some((Packet::Control(_), _)))
            ),
            "{:?}",
            action
        );

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert!(
            matches!(
                action,
                Action::RejectConnection(_, Some((Packet::Control(_), _)))
            ),
            "{:?}",
            action
        );

        let action = listener.handle_input(
            Instant::now(),
            Input::Success(ResultOf::RejectConnection(session_id())),
        );
        assert_eq!(action, Action::WaitForInput);
    }
}
