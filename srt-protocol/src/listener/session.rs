use std::{net::SocketAddr, time::Instant};

use crate::{
    packet::Packet, protocol::pending_connection::listen::Listen, settings::ConnInitSettings,
};

use super::*;

#[derive(Debug)]
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

    pub fn handle_packet<'s, 'a>(
        &'s mut self,
        now: Instant,
        session_id: SessionId,
        packet: (Packet, SocketAddr),
    ) -> Action<'a>
    where
        'a: 's,
    {
        use SessionState::*;
        let action = match self {
            Pending(listen) => (session_id, listen.handle_packet(now, Ok(packet))).into(),
            Rejecting(reject) => Action::RejectConnection(session_id, reject.clone()),
            // highest utilization path, no state transition needed, fast exit
            Open => return Action::DelegatePacket(session_id, packet),
            Dropping => Action::DropConnection(session_id),
        };
        self.transition_state_for(action)
    }

    pub fn handle_access_control_response<'s, 'a>(
        &'s mut self,
        now: Instant,
        session_id: SessionId,
        response: AccessControlResponse,
    ) -> Action<'a>
    where
        'a: 's,
    {
        use SessionState::*;
        let action = match self {
            Pending(listen) => (
                session_id,
                listen.handle_access_control_response(now, response),
            )
                .into(),
            Rejecting(reject) => Action::RejectConnection(session_id, reject.clone()),
            Open => Action::WaitForInput,
            Dropping => Action::DropConnection(session_id),
        };
        self.transition_state_for(action)
    }

    // pub fn handle_timer<'s, 'a>(&'s mut self, now: Instant, session_id: SessionId) -> Action<'a>
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

    fn transition_state_for<'a>(&mut self, action: Action<'a>) -> Action<'a> {
        match &action {
            Action::RejectConnection(_, rejection) => {
                *self = SessionState::Rejecting(rejection.clone())
            }
            Action::OpenConnection(_, _) => *self = SessionState::Open,
            Action::DropConnection(_) => *self = SessionState::Dropping,
            _ => {}
        };
        action
    }
}
