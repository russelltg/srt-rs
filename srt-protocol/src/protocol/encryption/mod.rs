use std::fmt::Debug;

use bytes::BytesMut;

use crate::{packet::*, settings::*};

pub mod key;
pub mod stream;
mod wrap;

#[derive(Debug, Eq, PartialEq)]
pub enum DecryptionError {
    // "Tried to decrypt but key was none"
    UnexpectedUnencryptedPacket(DataPacket),
    UnexpectedEncryptedPacket(DataPacket),
    EncryptionFailure,
    DecryptionFailure,
}

#[derive(Debug, Eq, PartialEq)]
pub enum KeyMaterialError {
    NoKeys, // "No keys!"
}

#[derive(Debug)]
pub struct Cipher {
    settings: Option<CipherSettings>,
    packets_encrypted: usize,
}

impl Cipher {
    pub fn new(settings: Option<CipherSettings>) -> Self {
        Self {
            settings,
            packets_encrypted: 0,
        }
    }

    pub fn encrypt(
        &mut self,
        mut packet: DataPacket,
    ) -> Option<(usize, DataPacket, Option<KeyingMaterialMessage>)> {
        match &mut self.settings {
            Some(cipher) => {
                // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
                let mut data = BytesMut::with_capacity(packet.payload.len());
                data.extend_from_slice(&packet.payload[..]);
                let active_sek = cipher.active_sek;
                let bytes =
                    cipher
                        .stream_encryption
                        .encrypt(active_sek, packet.seq_number, &mut data)?;
                packet.encryption = active_sek;
                packet.payload = data.freeze();
                Some((bytes, packet, None))
            }
            None => Some((0, packet, None)),
        }
    }

    pub fn decrypt(&self, packet: DataPacket) -> Result<(usize, DataPacket), DecryptionError> {
        use DecryptionError::*;
        let mut packet = packet;
        match (packet.encryption, &self.settings) {
            (DataEncryption::None, None) => Ok((0, packet)),
            (DataEncryption::None, Some(_)) => Err(UnexpectedUnencryptedPacket(packet)),
            (DataEncryption::Even | DataEncryption::Odd, None) => {
                Err(UnexpectedEncryptedPacket(packet))
            }
            (selected_sek, Some(cipher)) => {
                // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
                let mut data = BytesMut::with_capacity(packet.payload.len());
                data.extend_from_slice(&packet.payload[..]);
                let bytes = cipher
                    .stream_encryption
                    .decrypt(selected_sek, packet.seq_number, &mut data)
                    .ok_or(DecryptionFailure)?;
                packet.encryption = DataEncryption::None;
                packet.payload = data.freeze();
                Ok((bytes, packet))
            }
        }
    }

    pub fn refresh_key_material(
        &mut self,
        keying_material: KeyingMaterialMessage,
    ) -> Result<Option<KeyingMaterialMessage>, KeyMaterialError> {
        let cipher = self.settings.as_mut().ok_or(KeyMaterialError::NoKeys)?;
        cipher
            .update_with_key_material(&keying_material)
            .map_err(|_| KeyMaterialError::NoKeys)?;
        Ok(Some(keying_material))
    }

    pub fn validate_key_material(
        &self,
        _keying_material: KeyingMaterialMessage,
    ) -> Result<(), KeyMaterialError> {
        Ok(())
    }
}
