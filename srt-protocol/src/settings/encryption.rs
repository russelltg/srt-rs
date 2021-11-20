use std::convert::TryFrom;
use std::fmt::{self, Debug, Formatter};

pub use crate::{
    packet::{DataEncryption, KeyingMaterialMessage},
    protocol::encryption::{
        key::WrapInitializationVector,
        key::{EncryptionKey, Salt},
        stream::StreamEncryption,
        KeyMaterialError,
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

impl Debug for InvalidKeySizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid encryption key size. Valid sizes are 16, 24, or 32 bytes."
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Passphrase(String);

impl Passphrase {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<T: Into<String>> From<T> for Passphrase {
    fn from(value: T) -> Passphrase {
        Passphrase(value.into())
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase").finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySettings {
    pub key_size: KeySize,
    pub passphrase: Passphrase,

    /// KM Refresh Period specifies the number of packets to be sent
    /// before switching to the new SEK
    ///
    /// The recommended KM Refresh Period is after 2^25 packets encrypted
    /// with the same SEK are sent.
    pub km_refresh_period: usize,

    /// KM Pre-Announcement Period specifies when a new key is announced
    /// in a number of packets before key switchover.  The same value is
    /// used to determine when to decommission the old key after
    /// switchover.
    ///
    /// The recommended KM Pre-Announcement Period is 4000 packets (i.e.
    /// a new key is generated, wrapped, and sent at 2^25 minus 4000
    /// packets; the old key is decommissioned at 2^25 plus 4000
    /// packets).
    pub km_pre_announcement_period: usize,
    // TODO: implement KM Refresh Rate and KM Pre-Announce
    // See KM (Key Material) Refresh
    // https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-6
    // https://github.com/Haivision/srt/blob/master/docs/features/encryption.md
}

impl KeySettings {
    pub fn new(key_size: KeySize, passphrase: Passphrase) -> Self {
        Self {
            key_size,
            passphrase,
            km_refresh_period: 0,
            km_pre_announcement_period: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherSettings {
    pub key_settings: KeySettings,
    pub stream_encryption: StreamEncryption,
    pub active_sek: DataEncryption,
}

impl CipherSettings {
    pub fn new_random(key_settings: KeySettings) -> Self {
        Self {
            stream_encryption: StreamEncryption::new_random(key_settings.key_size),
            active_sek: DataEncryption::Even,
            key_settings,
        }
    }

    pub fn new(
        key_settings: &KeySettings,
        key_material: &KeyingMaterialMessage,
    ) -> Result<Self, WrapInitializationVector> {
        Ok(Self {
            key_settings: key_settings.clone(),
            stream_encryption: StreamEncryption::unwrap_from(
                &key_settings.passphrase,
                key_settings.key_size,
                key_material,
            )?,
            active_sek: DataEncryption::Even,
        })
    }

    pub fn wrap_keying_material(&self) -> Option<KeyingMaterialMessage> {
        self.stream_encryption
            .wrap_with(&self.key_settings.passphrase, self.key_settings.key_size)
    }

    pub fn update_with_key_material(
        &mut self,
        keying_material: &KeyingMaterialMessage,
    ) -> Result<(), WrapInitializationVector> {
        self.stream_encryption = StreamEncryption::unwrap_from(
            &self.key_settings.passphrase,
            self.key_settings.key_size,
            keying_material,
        )?;
        Ok(())
    }
}
