use std::{io, io::ErrorKind, net::IpAddr};

use thiserror::Error;

use crate::options::*;

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#list-of-options
#[derive(Error, Debug, Eq, PartialEq)]
pub enum OptionsError {
    #[error("KM Refresh Period ({0}) must be non-zero and greater than 1/2 the KM Pre Announce Period ({1}).")]
    KeyMaterialRefresh(PacketCount, PacketCount),
    #[error("Invalid password length: {0}. The password must be minimum 10 and maximum 79 characters long.")]
    PassphraseLength(usize),
    #[error("Invalid encryption key size: {0}. Valid sizes are 16, 24, or 32 bytes.")]
    InvalidKeySize(u8),

    #[error("MMS out of range: {0}. The maximum size of a UDP packet is 1500 bytes.")]
    MaxSegmentSizeOutOfRange(ByteCount),

    #[error("{0}")]
    ReceiveBufferMin(ByteCount),

    #[error("{buffer}, {max_segment}, {flow_control_window}")]
    ReceiveBufferTooLarge {
        buffer: ByteCount,
        max_segment: ByteCount,
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

    #[error("{0}")]
    InvalidStreamId(StreamIdError),
}

impl From<OptionsError> for io::Error {
    fn from(error: OptionsError) -> Self {
        Self::new(ErrorKind::InvalidInput, error)
    }
}
