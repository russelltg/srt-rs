use openssl::{
    aes::{self, AesKey, KeyError},
    error::ErrorStack,
    hash::MessageDigest,
    pkcs5::pbkdf2_hmac,
    rand::rand_bytes,
};

use crate::packet::{Auth, CipherType, PacketType, SrtKeyMessage};
use fmt::Debug;
use std::{error::Error, fmt};

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

pub struct CryptoManager {
    size: u8,
    passphrase: String,
    salt: [u8; 16],
    iv: [u8; 8],
    kek: Vec<u8>,
    key: Vec<u8>,
}

#[allow(dead_code)] // TODO: remove and flesh out this struct
impl CryptoManager {
    pub fn new_random(size: u8, passphrase: String) -> Self {
        let mut salt = [0; 16];
        rand_bytes(&mut salt[..]).unwrap();

        let mut key = vec![0; usize::from(size)];
        rand_bytes(&mut key[..]).unwrap();

        let mut iv = [0; 8];
        rand_bytes(&mut iv[..]);

        CryptoManager {
            size,
            passphrase,
            salt,
            iv,
            kek: vec![],
            key,
        }
    }

    pub fn new(size: u8, passphrase: String, salt: &[u8; 16], iv: &[u8; 8], key: Vec<u8>) -> Self {
        CryptoManager {
            size,
            passphrase,
            salt: *salt,
            iv: *iv,
            kek: vec![],
            key,
        }
    }

    pub fn generate_kmreq(&self) -> Result<SrtKeyMessage, CryptoError> {
        Ok(SrtKeyMessage {
            pt: PacketType::KeyingMaterial,
            keki: 0, // xxx
            cipher: CipherType::CTR,
            auth: Auth::None,
            salt: self.salt[..].into(),
            even_key: Some(self.key.clone()),
            odd_key: None,
            wrap_data: self.iv,
        })
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Generate the key encrypting key from the passphrase, caching it in the struct
    ///
    /// https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L69-L103
    pub fn generate_kek(&mut self) -> Result<&[u8], ErrorStack> {
        if !self.kek.is_empty() {
            // already cached
            return Ok(&self.kek[..]);
        }

        // the reference implementation uses the last 8 (at max) bytes of the salt. Sources:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L72
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L77-L85
        let salt_len = usize::min(8, self.salt.len());

        self.kek.resize(usize::from(self.size), 0);

        pbkdf2_hmac(
            self.passphrase.as_bytes(),
            &self.salt[self.salt.len() - salt_len..], // last salt_len bytes
            2048, // is what the reference implementation uses.https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L73
            MessageDigest::sha1(),
            &mut self.kek[..],
        )?;

        Ok(&self.kek[..])
    }

    /// Unwrap a key encrypted with the kek
    pub fn unwrap_key(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        self.generate_kek()?;

        self.key.resize(input.len() - 8, 0);

        aes::unwrap_key(
            &AesKey::new_decrypt(&self.kek[..]).unwrap(),
            None,
            &mut self.key,
            input,
        )?;
        Ok(())
    }

    pub fn wrap_key(&mut self) -> Result<Vec<u8>, CryptoError> {
        self.generate_kek()?;

        let mut ret = Vec::new();
        ret.resize(self.key.len() + 8, 0);

        aes::wrap_key(
            &AesKey::new_encrypt(&self.kek[..]).unwrap(),
            None,
            &mut ret[..],
            &self.key[..],
        )?;

        Ok(ret)
    }

    pub fn key(&self) -> &[u8] {
        &self.key
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

        let mut manager = CryptoManager::new(16, password.into(), &salt, &[0; 8], vec![]);
        let buf = manager.generate_kek().unwrap();

        assert_eq!(buf, &kek[..]);
    }

    #[test]
    fn wrap_key() {
        let mut manager = CryptoManager::new(
            16,
            "password123".into(),
            &b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22",
            &[0; 8],
            b"\r\xab\xc8n/2\xb4\xa7\xb9\xbb\xa2\xf31*\xe4\"".to_vec(),
        );
        assert_eq!(
            manager.generate_kek().unwrap(),
            &b"\xe9\xa0\xa4\x30\x2f\x59\xd0\x63\xc8\x83\x32\xbe\x35\x88\x82\x08"[..]
        );

        let _prev_key = Vec::from(manager.key());

        let wrapped = manager.wrap_key().unwrap();
        assert_eq!(
            wrapped,
            &b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..]
        );

        // manager.unwrap_key(&wrapped).unwrap();
        // assert_eq!(&prev_key[..], manager.key());
        let mut manager = CryptoManager::new(
            16,
            "password123".into(),
            &b"\x00\x00\x00\x00\x00\x00\x00\x00n\xd5+\x196\nq8",
            &[0; 8],
            vec![],
        );
        assert_eq!(
            manager.generate_kek().unwrap(),
            &b"\xde#\x1b\xfd9\x93z\xfb\xc3w\xa7\x80\xee\x80'\xa3"[..]
        );

        manager
            .unwrap_key(&b"U\x06\xe9\xfd\xdfd\xf1'nr\xf4\xe9f\x81#(\xb7\xb5D\x19{\x9b\xcdx"[..])
            .unwrap();
    }
}
