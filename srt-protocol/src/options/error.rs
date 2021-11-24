use thiserror::Error;

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#list-of-options
#[derive(Error, Debug, Eq, PartialEq)]
pub enum SocketOptionError {
    #[error("KM Refresh Period ({0}) must be non-zero and greater than 1/2 the KM Pre Announce Period ({1}).")]
    KeyMaterialRefresh(usize, usize),
    #[error("Invalid password length: {0}. The password must be minimum 10 and maximum 79 characters long.")]
    PassphraseLength(usize),
    #[error("Invalid encryption key size: {0}. Valid sizes are 16, 24, or 32 bytes.")]
    InvalidKeySize(u8),
}
