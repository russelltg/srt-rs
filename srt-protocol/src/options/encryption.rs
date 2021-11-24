use std::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

use super::SocketOptionError;

// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-6
// https://github.com/Haivision/srt/blob/master/docs/features/encryption.md
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionOptions {
    key: KeyOptions,
    key_refresh: KeyRefreshOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyOptions {
    // SRTO_PBKEYLEN - TODO: implement the "default"
    pub key_size: KeySize,
    // SRTO_PASSPHRASE
    pub passphrase: Passphrase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRefreshOptions {
    // SRTO_KMPREANNOUNCE
    /// KM Refresh Period specifies the number of packets to be sent
    /// before switching to the new SEK
    ///
    /// The recommended KM Refresh Period is after 2^25 packets encrypted
    /// with the same SEK are sent.
    pub period: usize,

    /// KM Pre-Announcement Period specifies when a new key is announced
    /// in a number of packets before key switchover.  The same value is
    /// used to determine when to decommission the old key after
    /// switchover.
    ///
    /// The recommended KM Pre-Announcement Period is 4000 packets (i.e.
    /// a new key is generated, wrapped, and sent at 2^25 minus 4000
    /// packets; the old key is decommissioned at 2^25 plus 4000
    /// packets).
    // SRTO_KMREFRESHRATE
    pub pre_announcement_period: usize,
}

impl KeyRefreshOptions {
    pub fn validate(self) -> Result<Self, SocketOptionError> {
        if self.period > 0 && self.period / self.pre_announcement_period >= 2 {
            Ok(self)
        } else {
            Err(SocketOptionError::KeyMaterialRefresh(
                self.period,
                self.pre_announcement_period,
            ))
        }
    }
}

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_passphrase
#[derive(Clone, Eq, PartialEq)]
pub struct Passphrase(String);

impl From<&'static str> for Passphrase {
    fn from(value: &'static str) -> Self {
        Self::try_from(value.to_string()).unwrap()
    }
}

impl TryFrom<String> for Passphrase {
    type Error = SocketOptionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !(10..=79).contains(&value.len()) {
            return Err(SocketOptionError::PassphraseLength(value.len()));
        }
        Ok(Passphrase(value))
    }
}

impl Passphrase {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Display for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Debug for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase").finish()
    }
}

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_pbkeylen
// TODO: revisit the 0/Default value scenario
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeySize {
    Bytes16,
    Bytes24,
    Bytes32,
}

impl KeySize {
    pub fn as_usize(self) -> usize {
        use KeySize::*;
        match self {
            Bytes16 => 16,
            Bytes24 => 24,
            Bytes32 => 32,
        }
    }
}

impl TryFrom<u8> for KeySize {
    type Error = SocketOptionError;

    fn try_from(value: u8) -> Result<Self, SocketOptionError> {
        use KeySize::*;
        match value {
            16 => Ok(Bytes16),
            24 => Ok(Bytes24),
            32 => Ok(Bytes32),
            value => Err(SocketOptionError::InvalidKeySize(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(
            format!("{:?}", Passphrase::from("1234567890")),
            "Passphrase"
        );
    }

    #[test]
    fn try_from() {
        use SocketOptionError::*;
        assert_eq!(
            Passphrase::try_from("123456789".to_string()),
            Err(PassphraseLength(9))
        );
        assert_eq!(
            Passphrase::try_from(String::from_utf8_lossy(&[b'X'; 80]).to_string()),
            Err(PassphraseLength(80))
        );
    }
}
