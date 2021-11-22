use std::fmt::Debug;

use aes::{cipher::StreamCipher, Aes128Ctr, Aes192Ctr, Aes256Ctr};

use crate::{
    packet::*,
    settings::{KeySettings, KeySize},
};

use super::key::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEncryptionKeys {
    salt: Salt,
    even_key: Option<EncryptionKey>,
    odd_key: Option<EncryptionKey>,
}

impl StreamEncryptionKeys {
    pub fn new(salt: Salt) -> Self {
        Self {
            salt,
            even_key: None,
            odd_key: None,
        }
    }

    pub fn new_random(key_size: KeySize) -> Self {
        Self {
            salt: Salt::new_random(),
            even_key: Some(EncryptionKey::new_random(key_size)),
            odd_key: Some(EncryptionKey::new_random(key_size)),
        }
    }

    pub fn commission_next_key(
        &mut self,
        active_sek: DataEncryption,
        key_settings: &KeySettings,
    ) -> Option<KeyingMaterialMessage> {
        use DataEncryption::*;
        match active_sek {
            Even => {
                self.odd_key = Some(EncryptionKey::new_random(key_settings.key_size));
            }
            Odd => self.odd_key = Some(EncryptionKey::new_random(key_settings.key_size)),
            None => return Option::None,
        }
        self.wrap_with(key_settings)
    }

    pub fn first_active_sek(&self) -> DataEncryption {
        if self.even_key.is_some() {
            DataEncryption::Even
        } else if self.odd_key.is_some() {
            DataEncryption::Odd
        } else {
            DataEncryption::None
        }
    }

    pub fn unwrap_from(
        key_settings: &KeySettings,
        key_material: &KeyingMaterialMessage,
    ) -> Result<Self, WrapInitializationVector> {
        // TODO: revisit errors, KeyingMaterialMessage has a lot of fields that ought be validated
        let salt = Salt::try_from(key_material.salt.as_slice()).unwrap();
        let kek = KeyEncryptionKey::new(key_settings, &salt);

        // TODO: this is raw input, return an error result on failure instead of assert
        assert_eq!(
            key_material.wrapped_keys.len(),
            key_material.key_flags.bits().count_ones() as usize * key_settings.key_size.as_usize()
                + 8
        );

        let wrapped_keys = key_material.wrapped_keys.as_slice();
        let keys = kek.decrypt_wrapped_keys(wrapped_keys)?;

        let key_flags = key_material.key_flags;
        let key_size = kek.len();
        let even_key = if key_flags.contains(KeyFlags::EVEN) {
            Some(EncryptionKey::try_from(&keys[0..key_size]).unwrap())
        } else {
            None
        };
        let odd_key = if key_flags.contains(KeyFlags::ODD) {
            Some(EncryptionKey::try_from(&keys[keys.len() - key_size..]).unwrap())
        } else {
            None
        };

        Ok(StreamEncryptionKeys {
            salt,
            even_key,
            odd_key,
        })
    }

    pub fn wrap_with(&self, key_settings: &KeySettings) -> Option<KeyingMaterialMessage> {
        let kek = KeyEncryptionKey::new(key_settings, &self.salt);

        let mut keys = Vec::new();
        if let Some(k) = &self.even_key {
            keys.extend(k.as_bytes());
        }
        if let Some(k) = &self.odd_key {
            keys.extend(k.as_bytes());
        }

        let wrapped_keys = kek.encrypt_wrapped_keys(keys.as_slice());

        Some(KeyingMaterialMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: match (&self.even_key, &self.odd_key) {
                (Some(_), Some(_)) => KeyFlags::EVEN | KeyFlags::ODD,
                (Some(_), None) => KeyFlags::EVEN,
                (None, Some(_)) => KeyFlags::ODD,
                (None, None) => return None,
            },
            keki: 0, // xxx
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: self.salt.as_slice().to_vec(),
            wrapped_keys,
        })
    }

    pub fn decrypt(
        &self,
        sek_selection: DataEncryption,
        seq_number: SeqNumber,
        data: &mut [u8],
    ) -> Option<usize> {
        let sek = self.get_key(sek_selection)?;
        let iv = self.salt.generate_strean_iv_for(seq_number);

        use cipher::NewCipher;
        let nonce = iv.as_bytes();
        use EncryptionKey::*;
        match sek {
            Bytes16(key) => Aes128Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
            Bytes24(key) => Aes192Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
            Bytes32(key) => Aes256Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
        };

        Some(data.len())
    }

    pub fn encrypt(
        &self,
        sek_selection: DataEncryption,
        seq_number: SeqNumber,
        data: &mut [u8],
    ) -> Option<usize> {
        let sek = self.get_key(sek_selection)?;
        let iv = self.salt.generate_strean_iv_for(seq_number);

        use cipher::NewCipher;
        let nonce = iv.as_bytes();
        use EncryptionKey::*;
        match sek {
            Bytes16(key) => Aes128Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
            Bytes24(key) => Aes192Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
            Bytes32(key) => Aes256Ctr::new(key.into(), nonce[..].into()).apply_keystream(data),
        };

        Some(data.len())
    }

    fn get_key(&self, active: DataEncryption) -> Option<&EncryptionKey> {
        use crate::packet::DataEncryption::*;
        match active {
            Even => self.even_key.as_ref(),
            Odd => self.odd_key.as_ref(),
            None => Option::None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn key_settings() -> KeySettings {
        KeySettings {
            key_size: KeySize::Bytes16,
            passphrase: "password123".into(),
        }
    }

    #[test]
    fn wrap_keys() {
        let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22";
        let stream_encryption = StreamEncryptionKeys {
            salt: Salt::try_from(salt).unwrap(),
            odd_key: None,
            even_key: EncryptionKey::try_from(b"\r\xab\xc8n/2\xb4\xa7\xb9\xbb\xa2\xf31*\xe4\"")
                .ok(),
        };

        let kek = KeyEncryptionKey::new(&key_settings(), &stream_encryption.salt);
        assert_eq!(
            kek.as_bytes(),
            b"\xe9\xa0\xa4\x30\x2f\x59\xd0\x63\xc8\x83\x32\xbe\x35\x88\x82\x08"
        );

        let expected_wrapped_keys =
            b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca";
        let expected_keying_material = KeyingMaterialMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: KeyFlags::EVEN,
            keki: 0,
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: salt.to_vec(),
            wrapped_keys: expected_wrapped_keys.to_vec(),
        };

        let keying_material = stream_encryption.wrap_with(&key_settings());
        assert_eq!(
            &keying_material.as_ref().unwrap().wrapped_keys[..],
            &expected_wrapped_keys[..]
        );

        assert_eq!(keying_material.unwrap(), expected_keying_material);
    }

    #[test]
    fn bad_password() {
        let key_settings = &KeySettings {
            key_size: KeySize::Bytes16,
            passphrase: "badpassword".into(),
        };
        let key_material = KeyingMaterialMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: KeyFlags::ODD,
            keki: 0,
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22"[..].into(),
            wrapped_keys: b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..]
                .into(),
        };

        let res = StreamEncryptionKeys::unwrap_from(key_settings, &key_material);

        assert!(matches!(res, Err(_)));
    }

    #[test]
    fn wrap_key2() {
        let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00n\xd5+\x196\nq8";
        let stream_encryption = StreamEncryptionKeys {
            salt: Salt::try_from(salt).unwrap(),
            odd_key: EncryptionKey::try_from(b"\r\xab\xc8n/2\xb4\xa7\xb9\xbb\xa2\xf31*\xe4\"").ok(),
            even_key: None,
        };

        let kek = KeyEncryptionKey::new(&key_settings(), &stream_encryption.salt);
        assert_eq!(
            kek.as_bytes(),
            b"\xde#\x1b\xfd9\x93z\xfb\xc3w\xa7\x80\xee\x80'\xa3"
        );

        let keying_material = KeyingMaterialMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: KeyFlags::ODD,
            keki: 0,
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: salt.to_vec(),
            wrapped_keys: b"U\x06\xe9\xfd\xdfd\xf1'nr\xf4\xe9f\x81#(\xb7\xb5D\x19{\x9b\xcdx"
                .to_vec(),
        };

        let stream_encryption =
            StreamEncryptionKeys::unwrap_from(&key_settings(), &keying_material).unwrap();

        assert_eq!(
            stream_encryption.wrap_with(&key_settings()),
            Some(keying_material)
        );
    }
}
