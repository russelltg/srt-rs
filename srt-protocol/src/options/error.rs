use std::{io, io::ErrorKind, net::IpAddr, time::Duration};

use thiserror::Error;

use crate::options::*;

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#list-of-options
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum OptionsError {
    #[error("KM Refresh Period ({0}) must be non-zero and greater than 1/2 the KM Pre Announce Period ({1}).")]
    KeyMaterialRefresh(PacketCount, PacketCount),
    #[error("Invalid password length: {0}. The password must be minimum 10 and maximum 79 characters long.")]
    PassphraseLength(usize),
    #[error("Invalid encryption key size: {0}. Valid sizes are 16, 24, or 32 bytes.")]
    InvalidKeySize(u8),

    #[error("MMS out of range: {0}. The maximum size of a UDP packet is 1500 bytes.")]
    MaxSegmentSizeOutOfRange(PacketSize),

    #[error("Receive buffer too small {0}")]
    ReceiveBufferMin(ByteCount),

    #[error("Receive buffer too big - buffer: {buffer}, max_segment: {max_segment}, flow_control_window: {flow_control_window}")]
    ReceiveBufferTooLarge {
        buffer: ByteCount,
        max_segment: PacketSize,
        flow_control_window: PacketCount,
    },

    #[error("UDP Receive buffer larger than flow window, flow window={flow_control_window} mss={max_segment}, receive buffer={udp_buffer}")]
    UdpReceiveBufferTooLarge {
        udp_buffer: ByteCount,
        max_segment: PacketSize,
        flow_control_window: PacketCount,
    },

    #[error("UDP Send buffer larger than flow window, flow window={flow_control_window} mss={max_segment}, receive buffer={udp_buffer}")]
    UdpSenderBufferTooLarge {
        udp_buffer: ByteCount,
        max_segment: PacketSize,
        flow_control_window: PacketCount,
    },

    #[error("Sender flow_control_window_size {0} is less than the minimum 32 packets")]
    FlowControlWindowMin(PacketCount),

    #[error("A specific local port is required to listen for incoming callers.")]
    LocalPortRequiredToListen,

    #[error("Mismatched remote address and local address family. remote: {0} local {1}")]
    MismatchedAddressFamilies(IpAddr, IpAddr),

    #[error("Invalid remote address")]
    InvalidRemoteAddress,

    #[error("Invalid local address")]
    InvalidLocalAddress,

    #[error("Invalid Stream Id {0}")]
    InvalidStreamId(StreamIdError),

    #[error("IP TTL is invalid, must be > 0")]
    InvalidIpTtl,

    #[error("Statistics interval is out of range: {0:?}. The minimum interval is 200ms.")]
    StatisticsIntervalOutOfRange(Duration),
}

impl From<OptionsError> for io::Error {
    fn from(error: OptionsError) -> Self {
        Self::new(ErrorKind::InvalidInput, error)
    }
}
