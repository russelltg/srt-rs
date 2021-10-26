pub mod connect;
mod cookie;
mod hsv5;
pub mod listen;
pub mod rendezvous;

use crate::protocol::sender::congestion_control::LiveBandwidthMode;
use crate::{
    crypto::CryptoOptions,
    packet::{ControlTypes, HandshakeControlInfo, RejectReason},
    Connection, DataPacket, Packet, SocketId,
};
use rand::random;
use std::{error::Error, fmt, net::SocketAddr, time::Duration};

#[non_exhaustive]
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConnectError {
    ControlExpected(DataPacket),
    HandshakeExpected(ControlTypes),
    InductionExpected(HandshakeControlInfo),
    WaveahandExpected(HandshakeControlInfo),
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
}

#[derive(Debug)]
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
}

#[derive(Debug, Clone)]
pub struct ConnInitSettings {
    pub local_sockid: SocketId,
    pub crypto: Option<CryptoOptions>,
    pub send_latency: Duration,
    pub recv_latency: Duration,
    pub bandwidth: LiveBandwidthMode,

    /// Receive buffer size in packets
    pub recv_buffer_size: usize,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ConnectError::*;
        match self {
            ControlExpected(pack) => write!(f, "Expected Control packet, found {:?}", pack),
            HandshakeExpected(got) => write!(f, "Expected Handshake packet, found: {:?}", got),
            InductionExpected(got) => write!(f, "Expected Induction (1) packet, found: {:?}", got),
            WaveahandExpected(got) => write!(f, "Expected Waveahand (0) packet, found: {:?}", got),
            AgreementExpected(got) => write!(f, "Expected Agreement (-2) packet, found: {:?}", got),
            UnexpectedHost(host, got) => write!(
                f,
                "Expected packets from different host, expected: {} found: {}",
                host, got
            ),
            ConclusionExpected(got) => {
                write!(f, "Expected Conclusion (-1) packet, found: {:?}", got)
            }
            UnsupportedProtocolVersion(got) => write!(
                f,
                "Unsupported protocol version, expected: v5 found v{0}",
                got
            ),
            InvalidHandshakeCookie(expected, got) => write!(
                f,
                "Received invalid cookie, expected {}, got {}",
                expected, got
            ),
            RendezvousExpected(got) => write!(f, "Expected rendezvous packet, got {:?}", got),
            CookiesMatched(cookie) => write!(
                f,
                "Cookies matched, waiting for a new cookie to resolve contest. Cookie: {}",
                cookie
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
        }
    }
}

impl Error for ConnectError {}

impl fmt::Display for ConnectionReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConnectionReject::*;
        match self {
            Rejecting(rr) => write!(f, "Local server rejected remote: {}", rr),
            Rejected(rr) => write!(f, "Remote rejected connection: {}", rr),
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

impl Default for ConnInitSettings {
    fn default() -> Self {
        ConnInitSettings {
            crypto: None,
            send_latency: Duration::from_millis(50),
            recv_latency: Duration::from_micros(50),
            local_sockid: random(),
            bandwidth: LiveBandwidthMode::default(),
            recv_buffer_size: 8192,
        }
    }
}
impl ConnInitSettings {
    pub fn copy_randomize(&self) -> ConnInitSettings {
        ConnInitSettings {
            crypto: self.crypto.clone(),
            send_latency: self.send_latency,
            recv_latency: self.recv_latency,
            local_sockid: random(),
            bandwidth: LiveBandwidthMode::default(),
            recv_buffer_size: 8192,
        }
    }
}
