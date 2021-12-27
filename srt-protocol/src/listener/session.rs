use std::{net::SocketAddr, time::Instant};

use crate::{
    connection::Connection,
    packet::Packet,
    protocol::pending_connection::{listen::Listen, ConnectionResult},
    settings::ConnInitSettings,
};

use super::*;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SessionState {
    Pending(Listen),
    Rejecting(Option<(Packet, SocketAddr)>),
    Dropping,
    Open,
}

impl SessionState {
    pub fn new_pending(settings: ConnInitSettings) -> Self {
        SessionState::Pending(Listen::new(settings, true))
    }

    pub fn handle_packet(
        &mut self,
        now: Instant,
        session_id: SessionId,
        packet: (Packet, SocketAddr),
    ) -> Action {
        use SessionState::*;
        match self {
            Pending(listen) => {
                let result = listen.handle_packet(now, Ok(packet));
                self.handle_connection_result(session_id, result)
            }
            Rejecting(reject) => Action::RejectConnection(session_id, reject.clone()),
            Open => Action::DelegatePacket(session_id, packet),
            Dropping => Action::DropConnection(session_id),
        }
    }

    pub fn handle_access_control_response(
        &mut self,
        now: Instant,
        session_id: SessionId,
        response: AccessControlResponse,
    ) -> Action {
        use SessionState::*;
        match self {
            Pending(listen) => {
                let result = listen.handle_access_control_response(now, response);
                self.handle_connection_result(session_id, result)
            }
            Rejecting(reject) => {
                let reject = reject.clone();
                self.reject(session_id, reject)
            }
            Open => unreachable!("this should not happen"),
            Dropping => Action::DropConnection(session_id),
        }
    }

    // pub fn handle_timer(&mut self, now: Instant, session_id: SessionId) -> Action
    // where
    //     'a: 's,
    // {
    //     use SessionState::*;
    //     match self {
    //         Pending(listen) => (session_id, listen.handle_timer(now)).into(),
    //         Rejecting(reject) => Action::DropConnection(session_id),
    //         Open => Action::WaitForInput,
    //         Dropping => Action::DropConnection(session_id),
    //     }
    // }

    fn handle_connection_result(
        &mut self,
        session_id: SessionId,
        result: ConnectionResult,
    ) -> Action {
        use ConnectionResult::*;
        match result {
            // TODO: do something with the error?
            NotHandled(_) => Action::WaitForInput,
            // TODO: do something with the rejection reason?
            Reject(p, _) => self.reject(session_id, p),
            SendPacket(p) => Action::SendPacket(p),
            Connected(p, c) => self.open(session_id, p, c),
            NoAction => Action::WaitForInput,
            RequestAccess(r) => Action::RequestAccess(session_id, r),
            // TODO: is this even a realistic failure mode since we handle I/O errors earlier up
            //  the call stack? if so, do something with the error?
            Failure(_) => self.drop(session_id),
        }
    }

    fn reject(&mut self, session_id: SessionId, packet: Option<(Packet, SocketAddr)>) -> Action {
        if !matches!(self, SessionState::Rejecting(_)) {
            *self = SessionState::Rejecting(packet.clone());
        }
        Action::RejectConnection(session_id, packet)
    }

    fn drop(&mut self, session_id: SessionId) -> Action {
        if !matches!(self, SessionState::Dropping) {
            *self = SessionState::Dropping;
        }
        Action::DropConnection(session_id)
    }

    fn open(
        &mut self,
        session_id: SessionId,
        packet: Option<(Packet, SocketAddr)>,
        connection: Connection,
    ) -> Action {
        if !matches!(self, SessionState::Open) {
            *self = SessionState::Open;
        }
        Action::OpenConnection(session_id, Box::new((packet, connection)))
    }
}
