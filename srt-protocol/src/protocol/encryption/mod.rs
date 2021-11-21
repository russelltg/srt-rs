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

#[cfg(test)]
mod cipher {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn round_trip() {
        let key_settings = KeySettings::new(KeySize::Bytes24, "test".into());
        let mut cipher = Cipher::new(Some(CipherSettings::new_random(&key_settings)));
        let original_packet = DataPacket {
            seq_number: SeqNumber(3),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: MsgNumber(1),
            timestamp: TimeStamp::MIN,
            dest_sockid: SocketId(0),
            payload: Bytes::from("test round_trip"),
        };

        let (bytes, encrypted_packet, key_material) =
            cipher.encrypt(original_packet.clone()).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_ne!(encrypted_packet, original_packet);
        assert_eq!(key_material, None);

        let (bytes, decrypted_packet) = cipher.decrypt(encrypted_packet.clone()).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);
    }

    #[test]
    fn decryption() {
        use DecryptionError::*;
        let new_packet = |encryption| DataPacket {
            seq_number: SeqNumber(3),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption,
            retransmitted: false,
            message_number: MsgNumber(1),
            timestamp: TimeStamp::MIN,
            dest_sockid: SocketId(0),
            payload: Bytes::from("test decryption"),
        };
        let with_encryption = |encrypt| {
            if encrypt {
                let key_settings = KeySettings::new(KeySize::Bytes24, "test".into());
                Cipher::new(Some(CipherSettings::new_random(&key_settings)))
            } else {
                Cipher::new(None)
            }
        };

        let packet = new_packet(DataEncryption::None);
        assert_eq!(
            with_encryption(true).decrypt(packet.clone()),
            Err(UnexpectedUnencryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::Even);
        assert_eq!(
            with_encryption(false).decrypt(packet.clone()),
            Err(UnexpectedEncryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::Odd);
        assert_eq!(
            with_encryption(false).decrypt(packet.clone()),
            Err(UnexpectedEncryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::None);
        assert_eq!(
            with_encryption(false).decrypt(packet.clone()),
            Ok((0, packet))
        );
    }

    #[test]
    fn refresh_key_material() {
        let key_settings = KeySettings::new(KeySize::Bytes24, "test".into());
        let mut cipher = Cipher::new(Some(CipherSettings::new_random(&key_settings)));
        let original_packet = DataPacket {
            seq_number: SeqNumber(3),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: MsgNumber(1),
            timestamp: TimeStamp::MIN,
            dest_sockid: SocketId(0),
            payload: Bytes::from("test refresh_key_material"),
        };

        let (first_bytes, first_packet, _) = cipher.encrypt(original_packet.clone()).unwrap();

        let stream_encryption = StreamEncryption::new_random(KeySize::Bytes24);
        let key_material = stream_encryption.wrap_with(&key_settings).unwrap();
        let response = cipher.refresh_key_material(key_material.clone());
        assert_eq!(response, Ok(Some(key_material)));

        let (second_bytes, second_packet, _) = cipher.encrypt(original_packet.clone()).unwrap();
        assert_eq!(first_bytes, second_bytes);
        assert_ne!(first_packet, second_packet);

        let (bytes, decrypted_packet) = cipher.decrypt(second_packet.clone()).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);
    }
}
