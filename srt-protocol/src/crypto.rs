use aes_ctr::{
    cipher::{NewBlockCipher, NewStreamCipher, SyncStreamCipher},
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
};
use aes_soft::{Aes128, Aes192, Aes256};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

use crate::{
    packet::{
        Auth, CipherType, CoreRejectReason, DataEncryption, KeyFlags, PacketType, SrtKeyMessage,
    },
    pending_connection::ConnectionReject,
    SeqNumber,
};
use fmt::Debug;
use rand::{rngs::OsRng, RngCore};
use std::{convert::TryInto, fmt};

mod wrap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoOptions {
    pub size: u8,
    pub passphrase: String,
}

// i would love for this to be not clone, maybe someday
#[derive(Clone)]
pub struct CryptoManager {
    options: CryptoOptions,
    salt: [u8; 16],
    kek: Vec<u8>,
    current_key: DataEncryption, // will only be either even or odd
    even_sek: Option<Vec<u8>>,
    odd_sek: Option<Vec<u8>>,
}

#[allow(dead_code)] // TODO: remove and flesh out this struct
impl CryptoManager {
    pub fn new_random(options: CryptoOptions) -> Self {
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt[..]);

        let mut even_key = vec![0; usize::from(options.size)];
        OsRng.fill_bytes(&mut even_key[..]);

        // let mut odd_key = vec![0; usize::from(options.size)];
        // rand_bytes(&mut odd_key[..]).unwrap();

        Self::new(options, &salt, Some(even_key), None) // TODO: should this generate both??
    }

    pub fn new_from_kmreq(
        options: CryptoOptions,
        kmreq: &SrtKeyMessage,
    ) -> Result<Self, ConnectionReject> {
        let salt = kmreq.salt[..].try_into().unwrap();
        let kek = CryptoManager::gen_kek(&options, &salt);

        assert_eq!(
            kmreq.wrapped_keys.len(),
            kmreq.key_flags.bits().count_ones() as usize * usize::from(options.size) + 8
        );

        let mut keys = vec![0; kmreq.wrapped_keys.len() - 8];

        let mut iv = [0; 8];
        match kek.len() {
            16 => wrap::aes_unwrap(
                &Aes128::new(kek[..].into()),
                &mut iv,
                &mut keys,
                &kmreq.wrapped_keys,
            ),
            24 => wrap::aes_unwrap(
                &Aes192::new(kek[..].into()),
                &mut iv,
                &mut keys,
                &kmreq.wrapped_keys,
            ),
            32 => wrap::aes_unwrap(
                &Aes256::new(kek[..].into()),
                &mut iv,
                &mut keys,
                &kmreq.wrapped_keys,
            ),
            _ => panic!("Invalid key size"),
        }

        if iv != wrap::DEFAULT_IV {
            return Err(ConnectionReject::Rejecting(
                CoreRejectReason::BadSecret.into(),
            ));
        }

        let even = if kmreq.key_flags.contains(KeyFlags::EVEN) {
            Some(keys[0..usize::from(options.size)].into())
        } else {
            None
        };
        let odd = if kmreq.key_flags.contains(KeyFlags::ODD) {
            Some((keys[keys.len() - usize::from(options.size)..]).into())
        } else {
            None
        };

        Ok(Self::new(options, &salt, even, odd))
    }

    fn new(
        options: CryptoOptions,
        salt: &[u8; 16],
        even_sek: Option<Vec<u8>>,
        odd_sek: Option<Vec<u8>>,
    ) -> Self {
        let kek = CryptoManager::gen_kek(&options, salt);
        CryptoManager {
            options,
            salt: *salt,
            kek,
            even_sek,
            odd_sek,
            current_key: DataEncryption::Even, // TODO: this is likely not right!
        }
    }

    fn gen_kek(options: &CryptoOptions, salt: &[u8; 16]) -> Vec<u8> {
        // Generate the key encrypting key from the passphrase, caching it in the struct
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L69-L103

        // the reference implementation uses the last 8 (at max) bytes of the salt. Sources:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L72
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_sa.c#L77-L85
        let salt_len = usize::min(8, salt.len());

        let mut kek = vec![0; usize::from(options.size)];

        pbkdf2::<Hmac<Sha1>>(
            options.passphrase.as_bytes(),
            &salt[salt.len() - salt_len..], // last salt_len bytes
            2048, // is what the reference implementation uses.https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/haicrypt.h#L73
            &mut kek[..],
        );

        kek
    }

    pub fn key_length(&self) -> u8 {
        self.options.size
    }

    pub fn generate_km(&self) -> SrtKeyMessage {
        SrtKeyMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: match (&self.even_sek, &self.odd_sek) {
                (Some(_), Some(_)) => KeyFlags::EVEN | KeyFlags::ODD,
                (Some(_), None) => KeyFlags::EVEN,
                (None, Some(_)) => KeyFlags::ODD,
                (None, None) => panic!("No keys!"),
            },
            keki: 0, // xxx
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: self.salt[..].into(),
            wrapped_keys: self.wrap_keys(),
        }
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
        out[0..14].copy_from_slice(&self.salt[..14]);

        for (i, b) in pki.0.to_be_bytes().iter().enumerate() {
            out[i + 10] ^= *b;
        }

        // TODO: the ref impl doesn't put ctr in here....
        // https://github.com/Haivision/srt/blob/9f7068d4f45eb3276e30fcc6e920f82b387c6852/haicrypt/hcrypt.h#L136-L136

        out
    }

    fn get_key(&self, enc: DataEncryption) -> &[u8] {
        &if enc == DataEncryption::Even {
            &self.even_sek
        } else {
            &self.odd_sek
        }
        .as_ref()
        .expect("Tried to decrypt but key was none")[..]
    }

    pub fn decrypt(&self, seq: SeqNumber, enc: DataEncryption, data: &mut [u8]) {
        let iv = self.gen_iv(seq).into();

        let key = self.get_key(enc);
        match key.len() {
            16 => Aes128Ctr::new(key[..].into(), &iv).apply_keystream(data),
            24 => Aes192Ctr::new(key[..].into(), &iv).apply_keystream(data),
            32 => Aes256Ctr::new(key[..].into(), &iv).apply_keystream(data),
            _ => panic!("inavlid cipher size"),
        }
    }

    pub fn encrypt(&self, seq: SeqNumber, data: &mut [u8]) -> DataEncryption {
        let iv = self.gen_iv(seq).into();

        let key = self.get_key(self.current_key);
        match key.len() {
            16 => Aes128Ctr::new(key[..].into(), &iv).apply_keystream(data),
            24 => Aes192Ctr::new(key[..].into(), &iv).apply_keystream(data),
            32 => Aes256Ctr::new(key[..].into(), &iv).apply_keystream(data),
            c => panic!("invalid cipher size {}", c),
        }
        self.current_key
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    fn wrap_keys(&self) -> Vec<u8> {
        let mut keys = Vec::new();

        if let Some(k) = &self.even_sek {
            keys.extend(k.iter());
        }
        if let Some(k) = &self.odd_sek {
            keys.extend(k.iter());
        }

        let mut ret = vec![0; keys.len() + 8];
        match self.kek.len() {
            16 => wrap::aes_wrap(
                &Aes128::new(self.kek[..].into()),
                None,
                &mut ret[..],
                &keys[..],
            ),
            24 => wrap::aes_wrap(
                &Aes192::new(self.kek[..].into()),
                None,
                &mut ret[..],
                &keys[..],
            ),
            32 => wrap::aes_wrap(
                &Aes256::new(self.kek[..].into()),
                None,
                &mut ret[..],
                &keys[..],
            ),
            _ => panic!("Invalid key size"),
        }

        ret
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
    use std::convert::TryInto;

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
        );

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
        );

        assert_eq!(
            manager.kek,
            &b"\xe9\xa0\xa4\x30\x2f\x59\xd0\x63\xc8\x83\x32\xbe\x35\x88\x82\x08"[..]
        );

        let wrapped = manager.wrap_keys();
        assert_eq!(
            wrapped,
            &b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..]
        );

        let m2 = CryptoManager::new_from_kmreq(
            manager.options.clone(),
            &SrtKeyMessage {
                pt: PacketType::KeyingMaterial,
                key_flags: KeyFlags::ODD,
                keki: 0,
                cipher: CipherType::Ctr,
                auth: Auth::None,
                salt: manager.salt.into(),
                wrapped_keys: wrapped,
            },
        )
        .unwrap();

        assert_eq!(m2.even_sek, manager.even_sek);
    }

    #[test]
    fn bad_password() {
        let wrapped =
            b"31ea\x11\xe8\xb0P\xfe\x99\x9f\xd5h\xc2b\xfb\x1a3\xcc\xc8\x9cNw\xca"[..].into();
        let res = CryptoManager::new_from_kmreq(
            CryptoOptions {
                size: 16,
                passphrase: "badpassword".into(),
            },
            &SrtKeyMessage {
                pt: PacketType::KeyingMaterial,
                key_flags: KeyFlags::ODD,
                keki: 0,
                cipher: CipherType::Ctr,
                auth: Auth::None,
                salt: b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22"[..]
                    .into(),
                wrapped_keys: wrapped,
            },
        );

        assert!(matches!(res, Err(_)));
    }

    #[test]
    fn wrap_key2() {
        let manager = CryptoManager::new(
            CryptoOptions {
                size: 16,
                passphrase: "password123".into(),
            },
            &b"\x00\x00\x00\x00\x00\x00\x00\x00n\xd5+\x196\nq8",
            None,
            None,
        );

        assert_eq!(
            manager.kek,
            &b"\xde#\x1b\xfd9\x93z\xfb\xc3w\xa7\x80\xee\x80'\xa3"[..]
        );

        CryptoManager::new_from_kmreq(
            manager.options.clone(),
            &SrtKeyMessage {
                pt: PacketType::KeyingMaterial,
                key_flags: KeyFlags::ODD,
                keki: 0,
                cipher: CipherType::Ctr,
                auth: Auth::None,
                salt: manager.salt.into(),
                wrapped_keys:
                    b"U\x06\xe9\xfd\xdfd\xf1'nr\xf4\xe9f\x81#(\xb7\xb5D\x19{\x9b\xcdx"[..].into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn gen_iv() {
        // example from the reference implementation
        let manager = CryptoManager::new(
            CryptoOptions {
                size: 16,
                passphrase: "password123".into(),
            },
            &hex::decode("87647f8a2361fb1a9e692de576985949").unwrap()[..]
                .try_into()
                .unwrap(),
            None,
            None,
        );

        assert_eq!(
            manager.gen_iv(SeqNumber(709520665)),
            &hex::decode("87647f8a2361fb1a9e6907af1b810000").unwrap()[..]
        );
    }
}
