use std::io::ErrorKind;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use thiserror::Error;

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#list-of-options
#[derive(Error, Debug, Eq, PartialEq)]
pub enum OptionsError {
    #[error("KM Refresh Period ({0}) must be non-zero and greater than 1/2 the KM Pre Announce Period ({1}).")]
    KeyMaterialRefresh(usize, usize),
    #[error("Invalid password length: {0}. The password must be minimum 10 and maximum 79 characters long.")]
    PassphraseLength(usize),
    #[error("Invalid encryption key size: {0}. Valid sizes are 16, 24, or 32 bytes.")]
    InvalidKeySize(u8),

    #[error("MMS out of range: {0}. The maximum size of a UDP packet is 1500 bytes.")]
    MaxSegmentSizeOutOfRange(usize),

    #[error("{0}")]
    ReceiveBufferMin(usize),

    #[error("{buffer}, {max_segment}, {flow_control_window}")]
    ReceiveBufferTooLarge {
        buffer: usize,
        max_segment: usize,
        flow_control_window: usize,
    },

    #[error("Sender flow_control_window_size {0} is less than the minimum 32 packets")]
    FlowControlWindowMin(usize),

    #[error("A specific local port is required to listen for incoming callers.")]
    LocalPortRequiredToListen,

    #[error("Mismatched remote address and local address family. remote: {0} local {0}")]
    MismatchedAddressFamilies(SocketAddr, IpAddr),

    #[error("Invalid remote address")]
    InvalidRemoteAddress,
}

impl From<OptionsError> for io::Error {
    fn from(error: OptionsError) -> Self {
        io::Error::new(ErrorKind::InvalidInput, error)
    }
}
