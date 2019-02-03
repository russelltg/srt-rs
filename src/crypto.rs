use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;

use failure::Error;

pub struct CryptoManager {
    size: u8,
    passphrase: String,
    salt: [u8; 16],
    kek: Vec<u8>,
    key: Vec<u8>,
}

impl CryptoManager {
    pub fn new(size: u8, passphrase: String) -> Self {
        let mut salt = [0; 16];
        rand_bytes(&mut salt[..]).unwrap();

        let mut key = vec![0; usize::from(size)];
        rand_bytes(&mut key[..]).unwrap();

        CryptoManager {
            size,
            passphrase,
            salt,
            kek: vec![],
            key,
        }
    }

    pub fn new_with_salt(size: u8, passphrase: String, salt: &[u8; 16], key: Vec<u8>) -> Self {
        CryptoManager {
            size,
            passphrase,
            salt: *salt,
            kek: vec![],
            key,
        }
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Generate the key encrypting key from the passphrase, caching it in the struct
    ///
    /// https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L69-L103
    pub fn generate_kek(&mut self) -> Result<&[u8], Error> {
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
    pub fn unwrap_key(&mut self) -> Result<(), Error> {
        let kek = self.generate_kek()?;

        unimplemented!()
    }

    pub fn wrap_key(&mut self) -> Result<&[u8], Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn kek_generate() {
        use binary_macros::*;

        // this is an example taken from the reference impl
        let password = "password123";
        let salt = base16!("7D59759C2B1A3F0B06C7028790C81C7D");
        let key = base16!("08F2758F41E4244D00057C9CEBEB95FC");

        let mut manager = CryptoManager::new_with_salt(16, password.into(), salt, vec![]);
        let buf = manager.generate_kek().unwrap();

        assert_eq!(buf, *key);
    }

}
