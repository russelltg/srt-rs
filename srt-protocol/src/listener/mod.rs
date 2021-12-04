mod input;
mod session;

use std::{collections::HashMap, io::Error, net::SocketAddr, time::Duration, time::Instant};

use crate::{packet::*, protocol::time::Timer, settings::ConnInitSettings};

use session::*;

pub use crate::protocol::pending_connection::{AccessControlRequest, AccessControlResponse};
pub use input::*;

#[derive(Clone, Debug)]
pub struct ListenerSettings {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListenerStatistics {
    rx_errors: u64,
}

#[derive(Debug)]
pub struct MultiplexListener {
    settings: ConnInitSettings,
    sessions: HashMap<SessionId, SessionState>,
    stats: ListenerStatistics,
    stats_timer: Timer,
}

impl MultiplexListener {
    pub fn new(now: Instant, settings: ConnInitSettings) -> Self {
        Self {
            settings,
            sessions: Default::default(),
            stats: Default::default(),
            stats_timer: Timer::new(now, Duration::from_secs(1)),
        }
    }

    pub fn handle_input(&mut self, now: Instant, input: Input) -> Action {
        match input {
            Input::Packet(packet) => self.handle_input_packet(now, packet),
            Input::AccessResponse(response) => self.handle_input_access_response(now, response),
            Input::Timer => self.handle_timer(now),
            Input::Success(result_of) => self.handle_success(now, result_of),
            Input::Failure(result_of) => self.handle_failure(now, result_of),
        }
    }

    fn handle_input_packet(&mut self, now: Instant, packet: ReceivePacketResult) -> Action {
        use ReceivePacketError::*;
        match packet {
            Ok(packet) => self.handle_packet(now, packet),
            Err(Io(error)) => self.handle_packet_receive_error(now, error),
            // TODO: maybe record statistics and/or log errors?
            Err(Parse(_)) => Action::WaitForInput,
        }
    }

    fn handle_input_access_response(
        &mut self,
        now: Instant,
        response: Option<(SessionId, AccessControlResponse)>,
    ) -> Action {
        match response {
            Some((session_id, response)) => {
                self.handle_access_control_response(now, session_id, response)
            }
            None => self.handle_close(),
        }
    }

    fn handle_packet(&mut self, now: Instant, packet: (Packet, SocketAddr)) -> Action {
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

    fn handle_packet_receive_error(&mut self, _now: Instant, _error: Error) -> Action {
        self.stats.rx_errors += 1;
        Action::WaitForInput
    }

    fn handle_access_control_response(
        &mut self,
        now: Instant,
        session_id: SessionId,
        response: AccessControlResponse,
    ) -> Action {
        match self.sessions.get_mut(&session_id) {
            Some(session) => session.handle_access_control_response(now, session_id, response),
            None => Action::DropConnection(session_id),
        }
    }

    fn handle_timer(&mut self, _now: Instant) -> Action {
        // TODO: create an action that returns an action with an Iterator that ticks time forward
        //  for all the sessions, yielding the results to the I/O loop
        Action::WaitForInput
    }

    fn handle_success(&mut self, _now: Instant, result_of: ResultOf) -> Action {
        use ResultOf::*;
        match result_of {
            SendPacket(_) => {}
            RequestAccess(_) => {}
            RejectConnection(session_id) => {
                self.sessions.remove(&session_id);
            }
            OpenConnection(_) => {}
            DelegatePacket(_) => {}
            DropConnection(session_id) => {
                self.sessions.remove(&session_id);
            }
            UpdateStatistics => {}
        }
        Action::WaitForInput
    }

    fn handle_failure(&self, _now: Instant, _result_of: ResultOf) -> Action {
        todo!()
    }

    fn handle_close(&mut self) -> Action {
        Action::Close
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
        let mut listener = MultiplexListener::new(Instant::now(), settings);

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
        let mut listener = MultiplexListener::new(Instant::now(), settings);

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
