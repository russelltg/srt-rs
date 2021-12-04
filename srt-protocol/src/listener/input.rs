use std::net::SocketAddr;

use crate::{
    connection::Connection,
    packet::{Packet, ReceivePacketResult, SocketId},
    protocol::pending_connection::ConnectionResult,
};

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SessionId(pub SocketAddr, pub SocketId);

#[derive(Debug, Eq, PartialEq)]
pub enum Input {
    Packet(ReceivePacketResult),
    AccessResponse(Option<(SessionId, AccessControlResponse)>),
    Success(ResultOf),
    Failure(ResultOf),
    Timer,
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

impl From<(SessionId, ConnectionResult)> for Action<'_> {
    fn from((session_id, result): (SessionId, ConnectionResult)) -> Self {
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
}

#[derive(Debug, Eq, PartialEq)]
pub enum ResultOf {
    SendPacket(SocketAddr),
    RequestAccess(SessionId),
    RejectConnection(SessionId),
    OpenConnection(SessionId),
    DelegatePacket(SessionId),
    DropConnection(SessionId),
    UpdateStatistics,
}

pub struct NextInputContext(Option<ResultOf>);

impl NextInputContext {
    pub fn for_action(action: &Action) -> Self {
        use crate::listener::Action::{Close, WaitForInput};
        use Action::*;
        let context = match action {
            SendPacket((_, address)) => Some(ResultOf::SendPacket(*address)),
            RequestAccess(id, _) => Some(ResultOf::RequestAccess(*id)),
            RejectConnection(id, _) => Some(ResultOf::RejectConnection(*id)),
            OpenConnection(id, _) => Some(ResultOf::OpenConnection(*id)),
            DelegatePacket(id, _) => Some(ResultOf::DelegatePacket(*id)),
            DropConnection(id) => Some(ResultOf::DropConnection(*id)),
            UpdateStatistics(_) => Some(ResultOf::UpdateStatistics),
            WaitForInput | Close => None,
        };
        Self(context)
    }

    pub fn input_from<T, E>(self, result: Result<T, E>) -> Input {
        let result_of = self.0.unwrap();
        match result {
            Ok(_) => Input::Success(result_of),
            Err(_) => Input::Failure(result_of),
        }
    }
}
