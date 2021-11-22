use std::convert::TryFrom;
use std::fmt::{self, Debug, Display, Formatter};

pub use crate::{
    packet::{DataEncryption, KeyingMaterialMessage},
    protocol::encryption::{
        key::WrapInitializationVector,
        key::{EncryptionKey, Salt},
        stream::{KeyMaterialError, StreamEncryptionKeys},
    },
};

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
    type Error = InvalidKeySizeError;

    fn try_from(value: u8) -> Result<Self, InvalidKeySizeError> {
        use KeySize::*;
        match value {
            16 => Ok(Bytes16),
            24 => Ok(Bytes24),
            32 => Ok(Bytes32),
            value => Err(InvalidKeySizeError(value)),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InvalidKeySizeError(u8);

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_pbkeylen
// TODO: revisit the 0/Default value scenario
impl Debug for InvalidKeySizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid encryption key size. Valid sizes are 16, 24, or 32 bytes."
        )
    }
}

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_passphrase
#[derive(Clone, Eq, PartialEq)]
pub struct Passphrase(String);

impl Passphrase {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&'static str> for Passphrase {
    fn from(value: &'static str) -> Self {
        Self::try_from(value.to_string()).unwrap()
    }
}

impl TryFrom<String> for Passphrase {
    type Error = PassphraseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !(10..=79).contains(&value.len()) {
            return Err(PassphraseError(value.len()));
        }
        Ok(Passphrase(value))
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase").finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PassphraseError(usize);

impl Display for PassphraseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid password length: {}. The password must be minimum 10 and maximum 79 characters long.", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySettings {
    pub key_size: KeySize,
    pub passphrase: Passphrase,
}

// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-6
// https://github.com/Haivision/srt/blob/master/docs/features/encryption.md
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMaterialRefreshSettings {
    period: usize,

    pre_announcement_period: usize,
}

impl Default for KeyMaterialRefreshSettings {
    fn default() -> Self {
        Self {
            pre_announcement_period: 4_000,
            period: 1 << 25, // 2^25
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct KeyMaterialRefreshSettingsError(usize, usize);

impl Display for KeyMaterialRefreshSettingsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KM Refresh Period ({}) must be non-zero and greater than the KM Pre Announce Period ({}).", self.0, self.1)
    }
}

impl KeyMaterialRefreshSettings {
    pub fn new(
        period: usize,
        pre_announcement_period: usize,
    ) -> Result<Self, KeyMaterialRefreshSettingsError> {
        if period > 0 && period > pre_announcement_period {
            Ok(Self {
                period,
                pre_announcement_period,
            })
        } else {
            Err(KeyMaterialRefreshSettingsError(
                period,
                pre_announcement_period,
            ))
        }
    }

    pub fn period(&self) -> usize {
        self.period
    }

    pub fn pre_announcement_period(&self) -> usize {
        self.pre_announcement_period
    }

    /// KM Refresh Period specifies the number of packets to be sent
    /// before switching to the new SEK
    ///
    /// The recommended KM Refresh Period is after 2^25 packets encrypted
    /// with the same SEK are sent.
    pub fn with_period(self, period: usize) -> Result<Self, KeyMaterialRefreshSettingsError> {
        Self::new(period, self.pre_announcement_period)
    }

    /// KM Pre-Announcement Period specifies when a new key is announced
    /// in a number of packets before key switchover.  The same value is
    /// used to determine when to decommission the old key after
    /// switchover.
    ///
    /// The recommended KM Pre-Announcement Period is 4000 packets (i.e.
    /// a new key is generated, wrapped, and sent at 2^25 minus 4000
    /// packets; the old key is decommissioned at 2^25 plus 4000
    /// packets).
    pub fn with_pre_announcement_period(
        self,
        pre_announcement_period: usize,
    ) -> Result<Self, KeyMaterialRefreshSettingsError> {
        Self::new(self.period, pre_announcement_period)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherSettings {
    pub key_settings: KeySettings,
    pub key_refresh: KeyMaterialRefreshSettings,
    pub stream_keys: StreamEncryptionKeys,
}

impl CipherSettings {
    pub fn new_random(key_settings: &KeySettings, km_refresh: &KeyMaterialRefreshSettings) -> Self {
        Self {
            key_settings: key_settings.clone(),
            key_refresh: km_refresh.clone(),
            stream_keys: StreamEncryptionKeys::new_random(key_settings.key_size),
        }
    }

    pub fn new(
        key_settings: &KeySettings,
        km_refresh: &KeyMaterialRefreshSettings,
        key_material: &KeyingMaterialMessage,
    ) -> Result<Self, KeyMaterialError> {
        Ok(Self {
            stream_keys: StreamEncryptionKeys::unwrap_from(key_settings, key_material)?,
            key_settings: key_settings.clone(),
            key_refresh: km_refresh.clone(),
        })
    }

    pub fn wrap_keying_material(&self) -> Option<KeyingMaterialMessage> {
        self.stream_keys.wrap_with(&self.key_settings)
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
        assert_eq!(
            Passphrase::try_from("123456789".to_string()),
            Err(PassphraseError(9))
        );
        assert_eq!(
            Passphrase::try_from(String::from_utf8_lossy(&[b'X'; 80]).to_string()),
            Err(PassphraseError(80))
        );
    }
}
