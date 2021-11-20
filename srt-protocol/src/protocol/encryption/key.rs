use std::{
    array::TryFromSliceError,
    convert::TryInto,
    fmt::{self, Debug, Formatter},
};

use aes::{Aes128, Aes192, Aes256};
use hmac::Hmac;
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;

use crate::{packet::SeqNumber, settings::KeySize};

use super::wrap;
use crate::settings::Passphrase;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Salt([u8; 16]);

impl Salt {
    pub fn new_random() -> Self {
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt[..]);
        Self(salt)
    }

    pub fn try_from(bytes: &[u8]) -> Result<Salt, TryFromSliceError> {
        Ok(Salt(bytes[..].try_into()?))
    }

    pub fn generate_strean_iv_for(&self, seq_number: SeqNumber) -> StreamInitializationVector {
        let salt = self.0;
        /* HaiCrypt-TP CTR mode IV (128-bit): (all these are in bytes)
         *    0   1   2   3   4   5  6   7   8   9   10  11  12  13  14  15
         * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * |                   0s                  |      pki      |  ctr  |
         * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         *                            XOR
         * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * |                         nonce                         +
         * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         *
         * pki    (32-bit): packet index (sequence number)
         * ctr    (16-bit): block counter
         * nonce (112-bit): number used once (first 12 bytes of salt)
         */
        let mut out = [0; 16];
        out[0..14].copy_from_slice(&salt[..14]);

        for (i, b) in seq_number.0.to_be_bytes().iter().enumerate() {
            out[i + 10] ^= *b;
        }

        // TODO: the ref impl doesn't put ctr in here....
        // https://github.com/Haivision/srt/blob/9f7068d4f45eb3276e30fcc6e920f82b387c6852/haicrypt/hcrypt.h#L136-L136

        StreamInitializationVector(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StreamInitializationVector([u8; 16]);

impl StreamInitializationVector {
    pub fn try_from(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        Ok(StreamInitializationVector(slice[..].try_into()?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for StreamInitializationVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "StreamIV(0x{})", hex::encode_upper(self.0))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WrapInitializationVector([u8; 8]);

impl WrapInitializationVector {
    pub fn try_from(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        Ok(WrapInitializationVector(slice[..].try_into()?))
    }
}

impl Debug for WrapInitializationVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KeyIV(0x{})", hex::encode_upper(self.0))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum EncryptionKey {
    Bytes16([u8; 16]),
    Bytes24([u8; 24]),
    Bytes32([u8; 32]),
}

impl EncryptionKey {
    pub fn new_random(size: KeySize) -> Self {
        use EncryptionKey::*;
        fn new_key<const N: usize>() -> [u8; N] {
            let mut key = [0u8; N];
            OsRng.fill_bytes(&mut key[..]);
            key
        }
        match size {
            KeySize::Bytes16 => Bytes16(new_key()),
            KeySize::Bytes24 => Bytes24(new_key()),
            KeySize::Bytes32 => Bytes32(new_key()),
        }
    }

    pub fn try_from(bytes: &[u8]) -> Result<EncryptionKey, TryFromSliceError> {
        use EncryptionKey::*;
        match bytes.len() {
            16 => Ok(Bytes16(bytes[..].try_into()?)),
            24 => Ok(Bytes24(bytes[..].try_into()?)),
            _ => Ok(Bytes32(bytes[..].try_into()?)),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        use EncryptionKey::*;
        match self {
            Bytes16(key) => key.len(),
            Bytes24(key) => key.len(),
            Bytes32(key) => key.len(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        use EncryptionKey::*;
        match self {
            Bytes16(key) => &key[..],
            Bytes24(key) => &key[..],
            Bytes32(key) => &key[..],
        }
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use EncryptionKey::*;
        match self {
            Bytes16(_) => f.debug_struct("EncryptionKey::Bytes16"),
            Bytes24(_) => f.debug_struct("EncryptionKey::Bytes24"),
            Bytes32(_) => f.debug_struct("EncryptionKey::Bytes32"),
        }
        .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KeyEncryptionKey(EncryptionKey);

impl KeyEncryptionKey {
    pub fn new(passphrase: &Passphrase, key_size: KeySize, salt: &Salt) -> Self {
        // Generate the key encrypting key from the passphrase, caching it in the struct
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L69-L103

        // the reference implementation uses the last 8 (at max) bytes of the salt. Sources:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L72
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L77-L85

        fn calculate_pbkdf2(passphrase: &Passphrase, salt: &Salt, key: &mut [u8]) {
            let salt = salt.0;
            // is what the reference implementation uses.https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L73
            const ROUNDS: u32 = 2048;
            let salt_len = usize::min(8, salt.len());
            pbkdf2::pbkdf2::<Hmac<Sha1>>(
                passphrase.as_bytes(),
                &salt[salt.len() - salt_len..], // last salt_len bytes
                ROUNDS,
                &mut *key,
            );
        }

        fn new_key<const N: usize>(passphrase: &Passphrase, salt: &Salt) -> [u8; N] {
            let mut key = [0u8; N];
            calculate_pbkdf2(passphrase, salt, &mut key);
            key
        }

        use EncryptionKey::*;
        let key = match key_size {
            KeySize::Bytes16 => Bytes16(new_key(passphrase, salt)),
            KeySize::Bytes24 => Bytes24(new_key(passphrase, salt)),
            KeySize::Bytes32 => Bytes32(new_key(passphrase, salt)),
        };

        KeyEncryptionKey(key)
    }

    pub fn encrypt_wrapped_keys(&self, keys: &[u8]) -> Vec<u8> {
        let mut encrypted_keys = vec![0; keys.len() + 8];
        use aes::NewBlockCipher;
        use EncryptionKey::*;
        match &self.0 {
            Bytes16(key) => wrap::aes_wrap(
                &Aes128::new(key[..].into()),
                None,
                &mut encrypted_keys,
                keys,
            ),
            Bytes24(key) => wrap::aes_wrap(
                &Aes192::new(key[..].into()),
                None,
                &mut encrypted_keys,
                keys,
            ),
            Bytes32(key) => wrap::aes_wrap(
                &Aes256::new(key[..].into()),
                None,
                &mut encrypted_keys,
                keys,
            ),
        }
        encrypted_keys
    }

    pub fn decrypt_wrapped_keys(
        &self,
        wrapped_keys: &[u8],
    ) -> Result<Vec<u8>, WrapInitializationVector> {
        use aes::NewBlockCipher;
        use EncryptionKey::*;
        let mut keys = vec![0; wrapped_keys.len() - 8];
        let mut iv = [0; 8];
        match &self.0 {
            Bytes16(key) => wrap::aes_unwrap(
                &Aes128::new(key[..].into()),
                &mut iv,
                &mut keys,
                wrapped_keys,
            ),
            Bytes24(key) => wrap::aes_unwrap(
                &Aes192::new(key[..].into()),
                &mut iv,
                &mut keys,
                wrapped_keys,
            ),
            Bytes32(key) => wrap::aes_unwrap(
                &Aes256::new(key[..].into()),
                &mut iv,
                &mut keys,
                wrapped_keys,
            ),
        }
        if iv != wrap::DEFAULT_IV {
            return Err(WrapInitializationVector(iv));
        }
        Ok(keys)
    }

    pub fn as_key(&self) -> &EncryptionKey {
        &self.0
    }
}

impl fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use EncryptionKey::*;
        match &self.0 {
            Bytes16(_) => f.debug_struct("KeyEncryptionKey::Bytes16"),
            Bytes24(_) => f.debug_struct("KeyEncryptionKey::Bytes24"),
            Bytes32(_) => f.debug_struct("KeyEncryptionKey::Bytes32"),
        }
        .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn kek_generate() {
        // this is an example taken from the reference impl
        let key_size = KeySize::Bytes16;
        let passphrase = "password123".to_string().into();
        let expected_kek = &hex::decode(b"08F2758F41E4244D00057C9CEBEB95FC").unwrap()[..];
        let salt =
            Salt::try_from(&hex::decode(b"7D59759C2B1A3F0B06C7028790C81C7D").unwrap()[..]).unwrap();

        let kek = KeyEncryptionKey::new(&passphrase, key_size, &salt);

        assert_eq!(kek.0.as_bytes(), expected_kek);
    }

    #[test]
    fn generate_iv() {
        // example from the reference implementation
        let salt =
            Salt::try_from(&hex::decode(b"87647f8a2361fb1a9e692de576985949").unwrap()[..]).unwrap();
        let expected_iv = StreamInitializationVector::try_from(
            &hex::decode(b"87647f8a2361fb1a9e6907af1b810000").unwrap()[..],
        )
        .unwrap();

        let iv = salt.generate_strean_iv_for(SeqNumber(709520665));

        assert_eq!(iv, expected_iv);
    }
}
