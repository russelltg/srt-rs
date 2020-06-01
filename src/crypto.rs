use openssl::{
    aes::{self, AesKey, KeyError},
    error::ErrorStack,
    hash::MessageDigest,
    pkcs5::pbkdf2_hmac,
    rand::rand_bytes,
};

use aes_ctr::{
    stream_cipher::{NewStreamCipher, SyncStreamCipher},
    Aes128Ctr,
};

use crate::{
    packet::{Auth, CipherType, DataEncryption, KeyFlags, PacketType, SrtKeyMessage},
    SeqNumber,
};
use fmt::Debug;
use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoOptions {
    pub size: u8,
    pub passphrase: String,
}

#[derive(Debug)]
pub enum CryptoError {
    Key(KeyError),
    Ssl(ErrorStack),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Key(ke) => ke.fmt(f),
            CryptoError::Ssl(es) => <ErrorStack as fmt::Display>::fmt(es, f),
        }
    }
}

impl Error for CryptoError {}

impl From<KeyError> for CryptoError {
    fn from(ke: KeyError) -> Self {
        CryptoError::Key(ke)
    }
}
impl From<ErrorStack> for CryptoError {
    fn from(es: ErrorStack) -> Self {
        CryptoError::Ssl(es)
    }
}

// i would love for this to be not clone, maybe someday
#[derive(Clone)]
pub struct CryptoManager {
    options: CryptoOptions,
    salt: [u8; 16],
    kek: Vec<u8>,
    even_key: Option<Vec<u8>>,
    odd_key: Option<Vec<u8>>,
}

#[allow(dead_code)] // TODO: remove and flesh out this struct
impl CryptoManager {
    pub fn new_random(options: CryptoOptions) -> Result<Self, CryptoError> {
        let mut salt = [0; 16];
        rand_bytes(&mut salt[..]).unwrap();

        let mut even_key = vec![0; usize::from(options.size)];
        rand_bytes(&mut even_key[..]).unwrap();

        let mut odd_key = vec![0; usize::from(options.size)];
        rand_bytes(&mut odd_key[..]).unwrap();

        Self::new(options, &salt, Some(even_key), Some(odd_key)) // TODO: should this generate both??
    }

    pub fn new(
        options: CryptoOptions,
        salt: &[u8; 16],
        even_key: Option<Vec<u8>>,
        odd_key: Option<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        // Generate the key encrypting key from the passphrase, caching it in the struct
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L69-L103

        // the reference implementation uses the last 8 (at max) bytes of the salt. Sources:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L72
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L77-L85
        let salt_len = usize::min(8, salt.len());

        let mut kek = vec![0; usize::from(options.size)];

        pbkdf2_hmac(
            options.passphrase.as_bytes(),
            &salt[salt.len() - salt_len..], // last salt_len bytes
            2048, // is what the reference implementation uses.https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L73
            MessageDigest::sha1(),
            &mut kek[..],
        )?;

        Ok(CryptoManager {
            options,
            salt: *salt,
            kek,
            even_key,
            odd_key,
        })
    }

    pub fn generate_km(&self) -> Result<SrtKeyMessage, CryptoError> {
        Ok(SrtKeyMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: match (&self.even_key, &self.odd_key) {
                (Some(_), Some(_)) => KeyFlags::EVEN | KeyFlags::ODD,
                (Some(_), None) => KeyFlags::EVEN,
                (None, Some(_)) => KeyFlags::ODD,
                (None, None) => panic!("No keys!"),
            },
            keki: 0, // xxx
            cipher: CipherType::CTR,
            auth: Auth::None,
            salt: self.salt[..].into(),
            wrapped_keys: self.wrap_keys()?,
        })
    }

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
    fn gen_iv(&self, pki: SeqNumber) -> [u8; 16] {
        let mut out = [0; 16];
        out[0..12].copy_from_slice(&self.salt[..12]);

        for (i, b) in pki.0.to_be_bytes().iter().enumerate() {
            out[i + 10] ^= b;
        }

        // TODO: the ref impl doesn't put ctr in here....
        // https://github.com/Haivision/srt/blob/9f7068d4f45eb3276e30fcc6e920f82b387c6852/haicrypt/hcrypt.h#L136-L136

        out
    }

    pub fn decrypt(&self, seq: SeqNumber, enc: DataEncryption, data: &mut [u8]) {
        let iv = self.gen_iv(seq).into();

        let key = if enc == DataEncryption::Even {
            &self.even_key
        } else {
            &self.odd_key
        }
        .as_ref()
        .expect("Tried to decrypt but key was none");

        match key.len() {
            16 => {
                let mut cipher = Aes128Ctr::new(key[..].into(), &iv);
                cipher.apply_keystream(data);
            }
            24 => unimplemented!(),
            32 => unimplemented!(),
            _ => panic!("inavlid cipher size"),
        }
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Unwrap a key encrypted with the kek
    pub fn unwrap_key(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut key = vec![0; input.len() - 8];

        aes::unwrap_key(
            &AesKey::new_decrypt(&self.kek[..]).unwrap(),
            None,
            &mut key,
            input,
        )?;
        Ok(key)
    }

    fn wrap_keys(&self) -> Result<Vec<u8>, CryptoError> {
        let mut keys = Vec::new();

        if let Some(k) = &self.even_key {
            keys.extend(k.iter());
        }
        if let Some(k) = &self.odd_key {
            keys.extend(k.iter());
        }

        let mut ret = vec![0; keys.len() + 8];
        aes::wrap_key(
            &AesKey::new_encrypt(&self.kek[..]).unwrap(),
            None,
            &mut ret[..],
            &keys[..],
        )?;

        Ok(ret)
    }
}

// don't print sensetive info
impl Debug for CryptoManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoManager {{ size={} }}", self.options.size)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn kek_generate() {
        // this is an example taken from the reference impl
        let password = "password123";
        let kek = hex::decode("08F2758F41E4244D00057C9CEBEB95FC").unwrap();
        let mut salt = [0; 16];
        salt.copy_from_slice(&hex::decode("7D59759C2B1A3F0B06C7028790C81C7D").unwrap());

        let manager = CryptoManager::new(
            CryptoOptions {
                size: 16,
                passphrase: password.into(),
            },
            &salt,
            None,
            None,
        )
        .unwrap();

        assert_eq!(manager.kek, &kek[..]);
    }

    #[test]
    fn wrap_key() {
        let manager = CryptoManager::new(
            CryptoOptions {
                size: 16,
                passphrase: "password123".into(),
            },
            &b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22",
            None,
            Some(b"\r\xab\xc8n/2\xb4\xa7\xb9\xbb\xa2\xf31*\xe4\"".to_vec()),
        )
        .unwrap();
        assert_eq!(
            manager.kek,
            &b"\xe9\xa0\xa4\x30\x2f\x59\xd0\x63\xc8\x83\x32\xbe\x35\x88\x82\x08"[..]
        );

        let wrapped = manager.wrap_keys().unwrap();
        assert_eq!(
            wrapped,
            &b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..]
        );

        // manager.unwrap_key(&wrapped).unwrap();
        // assert_eq!(&prev_key[..], manager.key());
        let manager = CryptoManager::new(
            CryptoOptions {
                size: 16,
                passphrase: "password123".into(),
            },
            &b"\x00\x00\x00\x00\x00\x00\x00\x00n\xd5+\x196\nq8",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            manager.kek,
            &b"\xde#\x1b\xfd9\x93z\xfb\xc3w\xa7\x80\xee\x80'\xa3"[..]
        );

        // manager
        //     .unwrap_key(&b"U\x06\xe9\xfd\xdfd\xf1'nr\xf4\xe9f\x81#(\xb7\xb5D\x19{\x9b\xcdx"[..])
        //     .unwrap();
    }
}
