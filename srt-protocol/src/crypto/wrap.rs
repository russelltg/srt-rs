//! Aes key wrapping is availble in OpenSSL rust, but it's the only thing we need from openssl...so I just ported OpenSSL's code to Rust
//! If a third-party library offers, this it would be better...

use cipher::generic_array::typenum::consts::U16;
use cipher::generic_array::{ArrayLength, GenericArray};
use cipher::BlockCipher;

pub const DEFAULT_IV: [u8; 8] = [0xA6; 8];

// from https://github.com/openssl/openssl/blob/81cae8ce0965afeb2dc1697d2a68ba3eb427be52/crypto/modes/wrap128.c#L53
// size_t CRYPTO_128_wrap(void *key, const unsigned char *iv,
//                        unsigned char *out,
//                        const unsigned char *in, size_t inlen,
//                        block128_f block)
// {
//     unsigned char *A, B[16], *R;
//     size_t i, j, t;
//     if ((inlen & 0x7) || (inlen < 16) || (inlen > CRYPTO128_WRAP_MAX))
//         return 0;
//     A = B;
//     t = 1;
//     memmove(out + 8, in, inlen);
//     if (!iv)
//         iv = default_iv;

//     memcpy(A, iv, 8);

//     for (j = 0; j < 6; j++) {
//         R = out + 8;
//         for (i = 0; i < inlen; i += 8, t++, R += 8) {
//             memcpy(B + 8, R, 8);
//             block(B, B, key);
//             A[7] ^= (unsigned char)(t & 0xff);
//             if (t > 0xff) {
//                 A[6] ^= (unsigned char)((t >> 8) & 0xff);
//                 A[5] ^= (unsigned char)((t >> 16) & 0xff);
//                 A[4] ^= (unsigned char)((t >> 24) & 0xff);
//             }
//             memcpy(R, B + 8, 8);
//         }
//     }
//     memcpy(out, A, 8);
//     return inlen + 8;
// }
pub fn aes_wrap<K>(key: &K, iv: Option<&[u8; 8]>, out: &mut [u8], input: &[u8])
where
    K: BlockCipher<BlockSize = U16>,
    <K as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    assert_eq!(input.len() & 0x7, 0);
    assert!(input.len() >= 8);
    assert_eq!(out.len(), input.len() + 8);

    let mut b = [0_u8; 16];

    let mut t = 1;
    out[8..].copy_from_slice(input);

    let iv = iv.unwrap_or(&DEFAULT_IV);
    b[..8].copy_from_slice(&iv[..]);

    for _ in 0..6 {
        let mut r = &mut out[8..];
        let mut i = 0;
        while i < input.len() {
            b[8..].copy_from_slice(&r[..8]);
            key.encrypt_block(GenericArray::from_mut_slice(&mut b[..16]));

            b[7] ^= (t & 0xff) as u8;
            if t > 0xff {
                b[6] ^= ((t >> 8) & 0xff) as u8;
                b[5] ^= ((t >> 16) & 0xff) as u8;
                b[4] ^= ((t >> 24) & 0xff) as u8;
            }
            r[..8].copy_from_slice(&b[8..]);

            i += 8;
            t += 1;
            r = &mut r[8..];
        }
    }
    out[..8].copy_from_slice(&b[..8]);
}

// from https://github.com/openssl/openssl/blob/81cae8ce0965afeb2dc1697d2a68ba3eb427be52/crypto/modes/wrap128.c#L104
// static size_t crypto_128_unwrap_raw(void *key, unsigned char *iv,
//                                     unsigned char *out,
//                                     const unsigned char *in, size_t inlen,
//                                     block128_f block)
// {
//     unsigned char *A, B[16], *R;
//     size_t i, j, t;
//     inlen -= 8;
//     if ((inlen & 0x7) || (inlen < 16) || (inlen > CRYPTO128_WRAP_MAX))
//         return 0;
//     A = B;
//     t = 6 * (inlen >> 3);
//     memcpy(A, in, 8);
//     memmove(out, in + 8, inlen);
//     for (j = 0; j < 6; j++) {
//         R = out + inlen - 8;
//         for (i = 0; i < inlen; i += 8, t--, R -= 8) {
//             A[7] ^= (unsigned char)(t & 0xff);
//             if (t > 0xff) {
//                 A[6] ^= (unsigned char)((t >> 8) & 0xff);
//                 A[5] ^= (unsigned char)((t >> 16) & 0xff);
//                 A[4] ^= (unsigned char)((t >> 24) & 0xff);
//             }
//             memcpy(B + 8, R, 8);
//             block(B, B, key);
//             memcpy(R, B + 8, 8);
//         }
//     }
//     memcpy(iv, A, 8);
//     return inlen;
// }
pub fn aes_unwrap<K>(key: &K, iv: &mut [u8; 8], out: &mut [u8], input: &[u8])
where
    K: BlockCipher<BlockSize = U16>,
    <K as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    assert_eq!(input.len(), out.len() + 8);
    assert_eq!(input.len() & 0x7, 0);
    assert!(input.len() > 16);

    let inlen = input.len() - 8;

    let mut b = [0; 16];
    let mut t = 6 * (inlen >> 3);
    b[..8].copy_from_slice(&input[..8]);
    out.copy_from_slice(&input[8..]);
    for _ in 0..6 {
        let mut r_offset = inlen;

        let mut i = 0;
        while i < inlen {
            r_offset -= 8;

            b[7] ^= (t & 0xff) as u8;
            if t > 0xff {
                b[6] ^= ((t >> 8) & 0xff) as u8;
                b[5] ^= ((t >> 16) & 0xff) as u8;
                b[4] ^= ((t >> 24) & 0xff) as u8;
            }
            b[8..].copy_from_slice(&out[r_offset..r_offset + 8]);
            key.decrypt_block(GenericArray::from_mut_slice(&mut b[..16]));
            out[r_offset..r_offset + 8].copy_from_slice(&b[8..16]);

            i += 8;
            t -= 1;
        }
    }
    iv.copy_from_slice(&b[..8])
}

#[cfg(test)]
mod test {
    use super::*;

    use aes_soft::cipher::NewBlockCipher;
    use aes_soft::*;

    // these are from https://tools.ietf.org/html/rfc3394#page-8
    #[test]
    fn example_4_1() {
        let kek =
            Aes128::new_varkey(&hex::decode("000102030405060708090A0B0C0D0E0F").unwrap()).unwrap();
        let to_wrap = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let mut out = [0; 24];
        aes_wrap(&kek, None, &mut out, &to_wrap);

        let expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        assert_eq!(expected, out);

        let mut out2 = [0; 16];
        let mut outiv = [0; 8];
        aes_unwrap(&kek, &mut outiv, &mut out2, &out);

        assert_eq!(to_wrap, out2);
        assert_eq!(outiv, DEFAULT_IV);
    }

    #[test]
    fn example_4_2() {
        let kek = Aes192::new_varkey(
            &hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap(),
        )
        .unwrap();
        let to_wrap = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let mut out = [0; 24];
        aes_wrap(&kek, None, &mut out, &to_wrap);

        let expected = hex::decode("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").unwrap();
        assert_eq!(expected, out);

        let mut out2 = [0; 16];
        let mut outiv = [0; 8];
        aes_unwrap(&kek, &mut outiv, &mut out2, &out);

        assert_eq!(to_wrap, out2);
        assert_eq!(outiv, DEFAULT_IV);
    }

    #[test]
    fn example_4_3() {
        let kek = Aes256::new_varkey(
            &hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
                .unwrap(),
        )
        .unwrap();
        let to_wrap = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let mut out = [0; 24];
        aes_wrap(&kek, None, &mut out, &to_wrap);

        let expected = hex::decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").unwrap();
        assert_eq!(expected, out);

        let mut out2 = [0; 16];
        let mut outiv = [0; 8];
        aes_unwrap(&kek, &mut outiv, &mut out2, &out);

        assert_eq!(to_wrap, out2);
        assert_eq!(outiv, DEFAULT_IV);
    }
}
