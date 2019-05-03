use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{self, Cipher};

use failure::{bail, Error};

pub struct CryptoManager {
    size: u8,
    passphrase: String,
    salt: [u8; 16],
    kek: Vec<u8>,
    key: Vec<u8>,
}

#[allow(dead_code)] // TODO: remove and flesh out this struct
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
    pub fn unwrap_key(&mut self, input: &[u8]) -> Result<(), Error> {
        self.generate_kek()?;

        self.key.resize(input.len() - 8, 0);
        if aes_unwrap_key(&self.kek[..], None, &mut self.key, input) {
            Ok(())
        } else {
            bail!("Failed to unwrap key")
        }
    }

    pub fn wrap_key(&mut self) -> Result<Vec<u8>, Error> {
        self.generate_kek()?;

        let mut ret = Vec::new();
        ret.resize(self.key.len() + 8, 0);

        if aes_wrap_key(&self.kek[..], None, &mut ret[..], &self.key[..]) {
            Ok(ret)
        } else {
            bail!("Failed to wrap key")
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}
const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

// AES_wrap_key -- adaptred froom hs_openssl_aes.c
fn aes_wrap_key(key: &[u8], iv: Option<&[u8]>, out: &mut [u8], input: &[u8]) -> bool {
    if (input.len() & 0x7 != 0) || (input.len() < 8) {
        return false;
    }
    out[8..].copy_from_slice(input);

    // use default if not specified
    let iv = iv.unwrap_or(&DEFAULT_IV);

    let mut b = [0; 16];
    b[..8].copy_from_slice(iv);

    let mut t: u32 = 1;

    for _ in 0..6 {
        for r in out[8..].chunks_mut(8) {
            b[8..].copy_from_slice(&r[..]);

            let mut src = [0; 24].to_vec();
            src[..16].copy_from_slice(&b[..]);
            let dest = symm::encrypt(Cipher::aes_128_ecb(), key, None, &src[..]).unwrap();
            b.copy_from_slice(&dest[..16]); // TODO: why 16 here?

            b[7] ^= t as u8;
            if t > 0xff {
                b[6] ^= (t >> 8) as u8;
                b[5] ^= (t >> 16) as u8;
                b[4] ^= (t >> 24) as u8;
            }
            r.copy_from_slice(&b[8..16]);

            t += 1;
        }
    }
    out[..8].copy_from_slice(&b[..8]);
    true
}

fn aes_unwrap_key(key: &[u8], iv: Option<&[u8]>, out: &mut [u8], input: &[u8]) -> bool {
    let inlen = input.len() as u32 - 8;

    if inlen & 0x7 != 0 {
        return false;
    }
    if inlen < 8 {
        return false;
    }
    let mut b = [0; 16];
    let iv = iv.unwrap_or(&DEFAULT_IV);
    // A = B;
    let mut t: u32 = 6 * (inlen >> 3);
    b[..8].copy_from_slice(&input[..8]);
    out.copy_from_slice(&input[8..]);
    for _ in 0..6 {
        // R = out + inlen - 8;
        // for (i = 0; i < inlen; i += 8, t--, R -= 8)
        for r in out.chunks_mut(8).rev() {
            b[7] ^= (t & 0xff) as u8;
            if t > 0xff {
                b[6] ^= ((t >> 8) & 0xff) as u8;
                b[5] ^= ((t >> 16) & 0xff) as u8;
                b[4] ^= ((t >> 24) & 0xff) as u8;
            }
            b[8..].copy_from_slice(r);

            let dest = symm::decrypt(Cipher::aes_128_ecb(), key, None, &b[..]).unwrap();
            b.copy_from_slice(&dest[..16]);

            r.copy_from_slice(&b[8..]);

            t -= 1;
        }
    }
    // TODO: cleanse?
    b == iv
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
        let kek = base16!("08F2758F41E4244D00057C9CEBEB95FC");

        let mut manager = CryptoManager::new_with_salt(16, password.into(), salt, vec![]);
        let buf = manager.generate_kek().unwrap();

        assert_eq!(buf, *kek);
    }

    #[test]
    fn wrap_key() {
        let mut manager = CryptoManager::new_with_salt(
            16,
            "password123".into(),
            &b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22",
            b"\r\xab\xc8n/2\xb4\xa7\xb9\xbb\xa2\xf31*\xe4\"".to_vec(),
        );
        assert_eq!(
            manager.generate_kek().unwrap(),
            &b"\xe9\xa0\xa4\x30\x2f\x59\xd0\x63\xc8\x83\x32\xbe\x35\x88\x82\x08"[..]
        );

        let prev_key = Vec::from(manager.key());

        let wrapped = manager.wrap_key().unwrap();
        assert_eq!(
            wrapped,
            &b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..]
        );

        // manager.unwrap_key(&wrapped).unwrap();
        // assert_eq!(&prev_key[..], manager.key());
        let mut manager = CryptoManager::new_with_salt(
            16,
            "password123".into(),
            &b"\x00\x00\x00\x00\x00\x00\x00\x00n\xd5+\x196\nq8",
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
