pub mod key;
pub mod stream;
mod wrap;

use std::fmt::Debug;

use bytes::BytesMut;

use crate::{packet::*, settings::*};

use stream::KeyMaterialError;

#[derive(Debug, Eq, PartialEq)]
pub enum DecryptionError {
    // "Tried to decrypt but key was none"
    UnexpectedUnencryptedPacket(DataPacket),
    UnexpectedEncryptedPacket(DataPacket),
    EncryptionFailure,
    DecryptionFailure,
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
        *stream_keys = StreamEncryptionKeys::unwrap_from(key_settings, &keying_material)?;
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
    packets_until_pre_announcement: usize,
    packets_until_transmit: usize,
    packets_until_key_switch: usize,
    last_key_material: Option<KeyingMaterialMessage>,
}

impl EncryptionState {
    fn try_encrypt_packet(&mut self, mut packet: DataPacket) -> Option<(usize, DataPacket)> {
        // this requires an extra copy here...maybe DataPacket should have a BytesMut in it instead...
        let mut data = BytesMut::with_capacity(packet.payload.len());
        data.extend_from_slice(&packet.payload[..]);
        let bytes = self
            .stream_keys
            .encrypt(self.active_sek, packet.seq_number, &mut data)?;
        packet.encryption = self.active_sek;
        packet.payload = data.freeze();
        Some((bytes, packet))
    }

    fn try_schedule_pre_announcment(&mut self) {
        if self.packets_until_pre_announcement == 0 {
            self.packets_until_pre_announcement = self.key_refresh.period();
            self.packets_until_transmit = 0;

            if self.last_key_material.is_none() {
                self.last_key_material = self
                    .stream_keys
                    .commission_next_key(self.active_sek, &self.key_settings);
            }
        }
    }

    fn try_send_key_material(&mut self) -> Option<KeyingMaterialMessage> {
        let km = self.last_key_material.as_ref()?;
        if self.packets_until_transmit == 0 {
            self.packets_until_transmit =
                std::cmp::min(self.key_refresh.pre_announcement_period(), 1_000);
            Some(km.clone())
        } else {
            self.packets_until_transmit -= 1;
            None
        }
    }

    fn try_switch_stream_keys(&mut self) {
        use DataEncryption::*;
        if self.packets_until_key_switch == 0 {
            self.packets_until_key_switch = self.key_refresh.period();
            if self.last_key_material.is_none() {
                self.active_sek = match self.active_sek {
                    Even => Odd,
                    Odd => Even,
                    None => None,
                };
            }
        }
    }
}

impl Encryption {
    pub fn new(settings: Option<CipherSettings>) -> Self {
        Self(settings.map(|settings| EncryptionState {
            key_settings: settings.key_settings,
            key_refresh: settings.key_refresh.clone(),
            stream_keys: settings.stream_keys,
            active_sek: DataEncryption::Even,

            packets_until_pre_announcement: settings.key_refresh.period()
                - settings.key_refresh.pre_announcement_period(),
            packets_until_transmit: 0,
            packets_until_key_switch: settings.key_refresh.period(),
            last_key_material: None,
        }))
    }

    pub fn encrypt(
        &mut self,
        packet: DataPacket,
    ) -> Option<(usize, DataPacket, Option<KeyingMaterialMessage>)> {
        match &mut self.0 {
            Some(this) => {
                let (bytes, packet) = this.try_encrypt_packet(packet)?;

                this.try_schedule_pre_announcment();
                this.try_switch_stream_keys();
                let km = this.try_send_key_material();

                this.packets_until_pre_announcement -= 1;
                this.packets_until_key_switch -= 1;

                Some((bytes, packet, km))
            }
            None => Some((0, packet, None)),
        }
    }

    pub fn handle_key_refresh_response(
        &mut self,
        keying_material: KeyingMaterialMessage,
    ) -> Result<(), KeyMaterialError> {
        use KeyMaterialError::*;
        if let Some(settings) = self.0.as_mut() {
            let expected_key_material = settings.last_key_material.as_ref().ok_or(NoKeys)?;
            if keying_material == *expected_key_material {
                settings.packets_until_transmit = 0;
                settings.last_key_material = None;
            } else {
                return Err(InvalidRefreshResponse(keying_material));
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
            key_size: KeySize::AES192,
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
            key_refresh: KeyMaterialRefreshSettings::new(3_000, 1_000).unwrap(),
            ..new_settings()
        };
        let mut encryption = Encryption::new(Some(settings.clone()));
        let mut decryption = Decryption::new(Some(settings.clone()));
        let original_packet = data_packet(DataEncryption::None, "test refresh_key_material");

        let count = settings.key_refresh.period() - settings.key_refresh.pre_announcement_period();
        for i in 0..count {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None);
            assert_eq!(packet.encryption, DataEncryption::Even, "{i:?}");
        }

        let (_, first_packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
        assert_ne!(km, None);
        assert_eq!(first_packet.encryption, DataEncryption::Even);

        let key_material = km.unwrap();
        let response = decryption.refresh_key_material(key_material.clone());
        assert_eq!(response, Ok(Some(key_material.clone())));

        assert_eq!(encryption.handle_key_refresh_response(key_material), Ok(()));

        for i in 0..settings.key_refresh.pre_announcement_period() {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None, "{i:?}");
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
        for _ in 1..count - 1 {
            let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
            assert_eq!(km, None);
            assert_eq!(packet.encryption, DataEncryption::Odd);
        }

        let (_, third_packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
        assert_ne!(km, None);
        assert_eq!(third_packet.encryption, DataEncryption::Odd);

        let key_material = km.unwrap();
        let response = decryption.refresh_key_material(key_material.clone());
        assert_eq!(response, Ok(Some(key_material)));

        let (bytes, decrypted_packet) = decryption.decrypt(third_packet).unwrap();
        assert_eq!(bytes, original_packet.payload.len());
        assert_eq!(decrypted_packet, original_packet);
    }

    #[test]
    fn retry_refresh_key_material() {
        let settings = CipherSettings {
            key_refresh: KeyMaterialRefreshSettings::new(44_000, 20_000).unwrap(),
            ..new_settings()
        };
        let mut encryption = Encryption::new(Some(settings.clone()));
        let original_packet = data_packet(DataEncryption::None, "test refresh_key_material");

        let mut km_resp = None;
        let count = (0..settings.key_refresh.period() - 10_000)
            // let count = (0..settings.key_refresh.period())
            .filter_map(|_| {
                let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
                if let Some(km) = &km {
                    km_resp = Some(km.clone());
                }
                km.map(|k| (packet.encryption, k))
            })
            .count();

        assert_eq!(count, 10);

        encryption
            .handle_key_refresh_response(km_resp.unwrap())
            .unwrap();

        let count = (0..10_000
            + (settings.key_refresh.period() - settings.key_refresh.pre_announcement_period()))
            .filter_map(|_| {
                let (_, packet, km) = encryption.encrypt(original_packet.clone()).unwrap();
                km.map(|k| (packet.encryption, k))
            })
            .count();

        // none received after the response
        assert_eq!(count, 0);
    }
}
