use std::net::SocketAddr;

use crate::{
    connection::Connection,
    packet::{Packet, ReceivePacketResult},
};

use super::*;

pub use crate::protocol::pending_connection::{AccessControlRequest, AccessControlResponse};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SessionId(pub SocketAddr);

#[derive(Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
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
