pub mod connect;
mod hsv5;
pub mod listen;
pub mod rendezvous;

pub(crate) mod cookie;

use std::{error::Error, fmt, io, net::SocketAddr};

use crate::{connection::Connection, options::StreamId, packet::*, settings::KeySettings};

#[non_exhaustive]
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConnectError {
    ControlExpected(DataPacket),
    HandshakeExpected(ControlTypes),
    InductionExpected(HandshakeControlInfo),
    WavehandExpected(HandshakeControlInfo),
    AgreementExpected(HandshakeControlInfo),
    UnexpectedHost(SocketAddr, SocketAddr),
    ConclusionExpected(HandshakeControlInfo),
    UnsupportedProtocolVersion(u32),
    InvalidHandshakeCookie(i32, i32),
    RendezvousExpected(HandshakeControlInfo),
    CookiesMatched(i32),
    ExpectedHsReq,
    ExpectedHsResp,
    ExpectedExtFlags,
    ExpectedNoExtFlags,
    ExpectedAccessControlResponse,
    ParseFailed(PacketParseError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct AccessControlRequest {
    pub local_socket_id: SocketId,
    pub remote: SocketAddr,
    pub remote_socket_id: SocketId,
    pub stream_id: Option<StreamId>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AccessControlResponse {
    Accepted(Option<KeySettings>),
    Rejected(RejectReason),
    Dropped,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConnectionReject {
    /// local rejected remote
    Rejecting(RejectReason),

    /// remote rejected local
    Rejected(RejectReason),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConnectionResult {
    NotHandled(ConnectError),
    Reject(Option<(Packet, SocketAddr)>, ConnectionReject),
    SendPacket((Packet, SocketAddr)),
    Connected(Option<(Packet, SocketAddr)>, Connection),
    NoAction,
    RequestAccess(AccessControlRequest),
    Failure(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ConnectError::*;
        match self {
            ControlExpected(pack) => write!(f, "Expected Control packet, found {pack:?}"),
            HandshakeExpected(got) => write!(f, "Expected Handshake packet, found: {got:?}"),
            InductionExpected(got) => write!(f, "Expected Induction (1) packet, found: {got:?}"),
            WavehandExpected(got) => write!(f, "Expected Waveahand (0) packet, found: {got:?}"),
            AgreementExpected(got) => write!(f, "Expected Agreement (-2) packet, found: {got:?}"),
            UnexpectedHost(host, got) => write!(
                f,
                "Expected packets from different host, expected: {host} found: {got}"
            ),
            ConclusionExpected(got) => {
                write!(f, "Expected Conclusion (-1) packet, found: {got:?}")
            }
            UnsupportedProtocolVersion(got) => write!(
                f,
                "Unsupported protocol version, expected: v5 found v{got}"
            ),
            InvalidHandshakeCookie(expected, got) => write!(
                f,
                "Received invalid cookie, expected {expected}, got {got}"
            ),
            RendezvousExpected(got) => write!(f, "Expected rendezvous packet, got {got:?}"),
            CookiesMatched(cookie) => write!(
                f,
                "Cookies matched, waiting for a new cookie to resolve contest. Cookie: {cookie}"
            ),
            ExpectedHsReq => write!(
                f,
                "Responder got handshake flags, but expected request, not response"
            ),
            ExpectedHsResp => write!(
                f,
                "Initiator got handshake flags, but expected response, not request"
            ),
            ExpectedExtFlags => write!(f, "Responder expected handshake flags, but got none"),
            ExpectedNoExtFlags => {
                write!(f, "Initiator did not expect handshake flags, but got some")
            }
            ParseFailed(e) => write!(f, "Failed to parse packet: {e}"),
            ExpectedAccessControlResponse => write!(
                f,
                "Expected an access control response but instead received a packet from the peer"
            ),
        }
    }
}

impl Error for ConnectError {}

impl fmt::Display for ConnectionReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConnectionReject::*;
        match self {
            Rejecting(rr) => write!(f, "Local server rejected remote: {rr}"),
            Rejected(rr) => write!(f, "Remote rejected connection: {rr}"),
        }
    }
}

impl ConnectionReject {
    fn reason(&self) -> RejectReason {
        match self {
            ConnectionReject::Rejecting(r) | ConnectionReject::Rejected(r) => *r,
        }
    }
}

impl Error for ConnectionReject {}
