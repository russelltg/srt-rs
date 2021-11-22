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
    Invalid(KeyingMaterialMessage),
}

#[derive(Debug)]
pub struct Decryption(Option<(StreamEncryptionKeys, KeySettings)>);

impl Decryption {
    pub fn new(settings: Option<CipherSettings>) -> Self {
        Self(settings.map(|settings| (settings.stream_keys, settings.key_settings)))
    }

    pub fn decrypt(&self, packet: DataPacket) -> Result<(usize, DataPacket), DecryptionError> {
        use DecryptionError::*;
        let mut packet = packet;
        match (packet.encryption, &self.0) {
            (DataEncryption::None, None) => Ok((0, packet)),
            (DataEncryption::None, Some(_)) => Err(UnexpectedUnencryptedPacket(packet)),
            (DataEncryption::Even | DataEncryption::Odd, None) => {
                Err(UnexpectedEncryptedPacket(packet))
            }
            (selected_sek, Some((stream_keys, _))) => {
                // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
                let mut data = BytesMut::with_capacity(packet.payload.len());
                data.extend_from_slice(&packet.payload[..]);
                let bytes = stream_keys
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
        let (stream_keys, key_settings) = self.0.as_mut().ok_or(KeyMaterialError::NoKeys)?;
        *stream_keys = StreamEncryptionKeys::unwrap_from(key_settings, &keying_material)
            .map_err(|_| KeyMaterialError::NoKeys)?;
        Ok(Some(keying_material))
    }
}

#[derive(Debug)]
pub struct Encryption(Option<EncryptionState>);

#[derive(Debug)]
struct EncryptionState {
    key_settings: KeySettings,
    key_refresh: KeyMaterialRefreshSettings,
    stream_keys: StreamEncryptionKeys,
    active_sek: DataEncryption,
    packets_until_preannounce: usize,
    packets_until_key_switch: usize,
}

impl Encryption {
    pub fn new(settings: Option<CipherSettings>) -> Self {
        Self(settings.map(|settings| EncryptionState {
            packets_until_preannounce: settings.key_refresh.period()
                - settings.key_refresh.pre_announcement_period(),
            packets_until_key_switch: settings.key_refresh.period(),
            key_settings: settings.key_settings,
            key_refresh: settings.key_refresh,
            stream_keys: settings.stream_keys,
            active_sek: DataEncryption::Even,
        }))
    }

    pub fn encrypt(
        &mut self,
        mut packet: DataPacket,
    ) -> Option<(usize, DataPacket, Option<KeyingMaterialMessage>)> {
        match &mut self.0 {
            Some(settings) => {
                // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
                let mut data = BytesMut::with_capacity(packet.payload.len());
                data.extend_from_slice(&packet.payload[..]);
                let active_sek = settings.active_sek;
                let bytes =
                    settings
                        .stream_keys
                        .encrypt(active_sek, packet.seq_number, &mut data)?;
                packet.encryption = active_sek;
                packet.payload = data.freeze();

                let km = if settings.packets_until_preannounce == 0 {
                    settings.packets_until_preannounce = settings.key_refresh.period();
                    settings
                        .stream_keys
                        .commission_next_key(active_sek, &settings.key_settings)
                    // TODO: need to retranmsit this until response
                } else {
                    None
                };

                if settings.packets_until_key_switch == 0 {
                    use DataEncryption::*;

                    settings.packets_until_key_switch = settings.key_refresh.period();
                    settings.active_sek = match active_sek {
                        Even => Odd,
                        Odd => Even,
                        None => None,
                    };
                }

                settings.packets_until_preannounce -= 1;
                settings.packets_until_key_switch -= 1;

                Some((bytes, packet, km))
            }
            None => Some((0, packet, None)),
        }
    }

    pub fn validate_key_material(
        &self,
        keying_material: KeyingMaterialMessage,
    ) -> Result<(), KeyMaterialError> {
        if let Some(settings) = self.0.as_ref() {
            if Some(&keying_material)
                != settings
                    .stream_keys
                    .wrap_with(&settings.key_settings)
                    .as_ref()
            {
                return Err(KeyMaterialError::Invalid(keying_material));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_settings() -> KeySettings {
        KeySettings {
            key_size: KeySize::Bytes24,
            passphrase: "1234567890".into(),
        }
    }

    fn new_settings() -> CipherSettings {
        CipherSettings::new_random(&key_settings(), &Default::default())
    }

    fn data_packet(encryption: DataEncryption, payload: &str) -> DataPacket {
        DataPacket {
            seq_number: SeqNumber(3),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption,
            retransmitted: false,
            message_number: MsgNumber(1),
            timestamp: TimeStamp::MIN,
            dest_sockid: SocketId(0),
            payload: bytes::Bytes::copy_from_slice(payload.as_bytes()),
        }
    }

    #[test]
    fn round_trip() {
        let settings = new_settings();
        let original_packet = data_packet(DataEncryption::None, "test round_trip");

        let mut encryption = Encryption::new(Some(settings.clone()));
        let (bytes, encrypted_packet, key_material) =
            encryption.encrypt(original_packet.clone()).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_ne!(encrypted_packet, original_packet);
        assert_eq!(key_material, None);

        let decryption = Decryption::new(Some(settings));
        let (bytes, decrypted_packet) = decryption.decrypt(encrypted_packet).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);
    }

    #[test]
    fn decryption_falure() {
        use DecryptionError::*;
        let with_keys = |with_keys| {
            if with_keys {
                Decryption::new(Some(new_settings()))
            } else {
                Decryption::new(None)
            }
        };

        let new_packet = |encryption| data_packet(encryption, "test decryption_falureR");

        let packet = new_packet(DataEncryption::None);
        assert_eq!(
            with_keys(true).decrypt(packet.clone()),
            Err(UnexpectedUnencryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::Even);
        assert_eq!(
            with_keys(false).decrypt(packet.clone()),
            Err(UnexpectedEncryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::Odd);
        assert_eq!(
            with_keys(false).decrypt(packet.clone()),
            Err(UnexpectedEncryptedPacket(packet))
        );

        let packet = new_packet(DataEncryption::None);
        assert_eq!(with_keys(false).decrypt(packet.clone()), Ok((0, packet)));
    }

    #[test]
    fn refresh_key_material() {
        let settings = CipherSettings {
            key_refresh: KeyMaterialRefreshSettings::new(5, 2).unwrap(),
            ..new_settings()
        };
        let mut encryption = Encryption::new(Some(settings.clone()));
        let mut decryption = Decryption::new(Some(settings.clone()));
        let original_packet = data_packet(DataEncryption::None, "test refresh_key_material");

        let count = settings.key_refresh.period() - settings.key_refresh.pre_announcement_period();
        for _ in 0..count {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None);
            assert_eq!(packet.encryption, DataEncryption::Even);
        }

        let (_, first_packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
        assert_ne!(km, None);
        assert_eq!(first_packet.encryption, DataEncryption::Even);

        let key_material = km.unwrap();
        let response = decryption.refresh_key_material(key_material.clone());
        assert_eq!(response, Ok(Some(key_material)));

        for _ in 0..settings.key_refresh.pre_announcement_period() {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None);
            assert_eq!(packet.encryption, DataEncryption::Even);
        }

        let (_, second_packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
        assert_eq!(km, None);
        assert_eq!(second_packet.encryption, DataEncryption::Odd);

        let (bytes, decrypted_packet) = decryption.decrypt(first_packet).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);

        let (bytes, decrypted_packet) = decryption.decrypt(second_packet).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);

        let count = settings.key_refresh.period() - settings.key_refresh.pre_announcement_period();
        for _ in 0..count {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None);
            assert_eq!(packet.encryption, DataEncryption::Even);
        }

        let (_, third_packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
        assert_ne!(km, None);
        assert_eq!(third_packet.encryption, DataEncryption::Even);

        let key_material = km.unwrap();
        let response = decryption.refresh_key_material(key_material.clone());
        assert_eq!(response, Ok(Some(key_material)));

        let (bytes, decrypted_packet) = decryption.decrypt(third_packet).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);
    }
}
