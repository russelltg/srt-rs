use std::{collections::HashMap, io::Error, net::SocketAddr, time::Duration, time::Instant};

use crate::{
    connection::Connection,
    packet::*,
    protocol::{
        pending_connection::{listen::Listen, ConnectionResult},
        time::Timer,
    },
    settings::ConnInitSettings,
};

pub use crate::protocol::pending_connection::{AccessControlRequest, AccessControlResponse};

#[derive(Clone, Debug)]
pub struct ListenerSettings {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SessionId(pub SocketAddr, pub SocketId);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListenerStatistics {
    rx_errors: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Input {
    Packet(ReceivePacketResult),
    AccessResponse(Option<(SessionId, AccessControlResponse)>),
    Timer,

    PacketSent(usize),

    ConnectionClosed(SessionId),
    AccessRequested(SessionId),
    ConnectionRejected(SessionId),
    ConnectionOpened(SessionId),
    ConnectionDropped(SessionId),
    PacketDelegated(SessionId),
    StatisticsUpdated,

    Failure(ActionError),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Action<'a> {
    SendPacket((Packet, SocketAddr)),
    RequestAccess(SessionId, AccessControlRequest),
    RejectConnection(SessionId, Option<(Packet, SocketAddr)>),
    OpenConnection(SessionId, Box<(Option<(Packet, SocketAddr)>, Connection)>),
    DelegatePacket(SessionId, (Packet, SocketAddr)),
    DropConnection(SessionId),
    UpdateStatistics(&'a ListenerStatistics),
    WaitForInput,
    Close,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ActionError {
    SendPacketFailed,
    ReceivePacketFailed,
    SendStatistics,
    RequestAccessFailed(SessionId),
    PendingConnectionMissing(SessionId),
    ActiveConnectionMissing(SessionId),
    OpenConnectionFailed(SessionId),
    DelegatePacketFailed(SessionId),
}

#[derive(Debug)]
pub struct MultiplexListener {
    settings: ConnInitSettings,
    sessions: HashMap<SessionId, Option<Listen>>,
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
            _ => Action::WaitForInput,
            // TODO: are these even useful? maybe for statistics (e.g. PacketSent(usize)
            // Input::ConnectionClosed(_) => {}
            // Input::PacketSent(_) => {}
            // Input::AccessRequested(_) => {}
            // Input::ConnectionOpened(_) => {}
            // Input::ConnectionDropped(_) => {}
            // Input::PacketDelegated(_) => {}
            // Input::StatisticsUpdated => {}
            // Input::Failure(_) => {}
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
        let sessions = &mut self.sessions;
        let session = match sessions.get_mut(&session_id) {
            None => {
                let _ = self.sessions.insert(
                    session_id.clone(),
                    Some(Listen::new(self.settings.clone(), true)),
                );
                self.sessions.get_mut(&session_id).unwrap()
            }
            Some(s) => s,
        };

        let action = match session {
            Some(listen) => {
                let result = listen.handle_packet(now, Ok(packet));
                Self::action_from_listen_result(session_id, result)
            }
            None => Action::DelegatePacket(session_id, packet),
        };

        if matches!(action, Action::RejectConnection(_, _)) {
            *session = None;
        }

        action
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
            Some(listen) => {
                match listen.take() {
                    Some(mut listen) => {
                        let result = listen.handle_access_control_response(now, response);
                        Self::action_from_listen_result(session_id, result)
                    }
                    // TODO: log error, panic? this shouldn't happen
                    None => Action::WaitForInput,
                }
            }
            None => Action::DropConnection(session_id),
        }
    }

    fn handle_close(&mut self) -> Action {
        self.sessions.clear();
        Action::Close
    }

    fn action_from_listen_result<'a>(
        session_id: SessionId,
        result: ConnectionResult,
    ) -> Action<'a> {
        use ConnectionResult::*;
        match result {
            // TODO: do something with the error?
            NotHandled(_) => Action::WaitForInput,
            // TODO: do something with the rejection reason?
            Reject(p, _) => Action::RejectConnection(session_id, p),
            SendPacket(p) => Action::SendPacket(p),
            Connected(p, c) => Action::OpenConnection(session_id, Box::new((p, c))),
            NoAction => Action::WaitForInput,
            RequestAccess(r) => Action::RequestAccess(session_id, r),
            // TODO: is this even a realistic failure mode since we handle I/O errors earlier up
            //  the call stack? if so, do something with the error?
            Failure(_) => Action::DropConnection(session_id),
        }
    }

    fn handle_timer(&self, _now: Instant) -> Action {
        // TODO: we need to scan all the pending sessions and push the clock forward
        Action::WaitForInput
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use rand::random;

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

        let action = listener.handle_input(Instant::now(), Input::ConnectionOpened(session_id()));
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
}
