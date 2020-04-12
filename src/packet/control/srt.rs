use std::time::Duration;

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use failure::{bail, Error};
use log::warn;

use crate::SrtVersion;

/// The SRT-specific control packets
/// These are `Packet::Custom` types
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SrtControlPacket {
    /// SRT handshake reject
    /// ID = 0
    Reject,

    /// SRT handshake request
    /// ID = 1
    HandshakeRequest(SrtHandshake),

    /// SRT handshake response
    /// ID = 2
    HandshakeResponse(SrtHandshake),

    /// Key manager request
    /// ID = 3
    KeyManagerRequest(SrtKeyMessage),

    /// Key manager response
    /// ID = 4
    KeyManagerResponse(SrtKeyMessage),

    /// StreamID(?) // TODO: research
    /// ID = 5
    StreamId,

    /// Smoother? // TODO: research
    /// ID = 6
    Smoother,
}

/// from https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_msg.h#L76-L96
///
/// HaiCrypt KMmsg (Keying Material):
///
/// ```ignore,
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// +0x00 |0|Vers |   PT  |             Sign              |    resv   |KF |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// +0x04 |                              KEKI                             |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// +0x08 |    Cipher     |      Auth     |      SE       |     Resv1     |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// +0x0C |             Resv2             |     Slen/4    |     Klen/4    |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// +0x10 |                              Salt                             |
///       |                              ...                              |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
///       |                              Wrap                             |
///       |                              ...                              |
///       +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
/// ```
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrtKeyMessage {
    pub pt: u8,
    pub sign: u16,
    pub keki: u32,
    pub cipher: CipherType,
    pub auth: u8,
    pub se: u8,
    pub salt: Vec<u8>,
    pub even_key: Option<Vec<u8>>,
    pub odd_key: Option<Vec<u8>>,

    /// The data for unwrapping the key. TODO: research more
    /// RFC 3394
    pub wrap_data: [u8; 8],
}

/// from https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_msg.h#L121-L124
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CipherType {
    None = 0,
    ECB = 1,
    CTR = 2,
    CBC = 3,
}

/// The SRT handshake object
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SrtHandshake {
    /// The SRT version
    /// Serialized just as the u32 that SrtVersion serialized to
    pub version: SrtVersion,

    /// SRT connection init flags
    pub flags: SrtShakeFlags,

    /// The peer's TSBPD latency
    /// This is serialized as the upper 16 bits of the third 32-bit word
    /// source: https://github.com/Haivision/srt/blob/4f7f2beb2e1e306111b9b11402049a90cb6d3787/srtcore/core.cpp#L1341-L1353
    pub peer_latency: Duration,

    /// The TSBPD latency
    /// This is serialized as the lower 16 bits of the third 32-bit word
    /// see csrtcc.cpp:132 in the reference implementation
    pub latency: Duration,
}

bitflags! {
    pub struct SrtShakeFlags: u32 {
        /// Timestamp-based Packet delivery real-time data sender
        const TSBPDSND = 0x1;

        /// Timestamp-based Packet delivery real-time data receiver
        const TSBPDRCV = 0x2;

        /// HaiCrypt AES-128/192/256-CTR
        const HAICRYPT = 0x4;

        /// Drop real-time data packets too late to be processed in time
        const TLPKTDROP = 0x8;

        /// Periodic NAK report
        const NAKREPORT = 0x10;

        /// One bit in payload packet msgno is "retransmitted" flag
        const REXMITFLG = 0x20;

        /// Not entirely sure what this means.... TODO:
        const STREAM = 0x40;

        /// Again not sure... TODO:
        const FILTERCAP = 0x80;
    }
}

impl SrtControlPacket {
    pub fn parse<T: Buf>(packet_type: u16, buf: &mut T) -> Result<SrtControlPacket, Error> {
        use self::SrtControlPacket::*;

        match packet_type {
            0 => Ok(Reject),
            1 => Ok(HandshakeRequest(SrtHandshake::parse(buf)?)),
            2 => Ok(HandshakeResponse(SrtHandshake::parse(buf)?)),
            3 => Ok(KeyManagerRequest(SrtKeyMessage::parse(buf)?)),
            4 => Ok(KeyManagerResponse(SrtKeyMessage::parse(buf)?)),
            _ => bail!("Unrecognized custom packet type {}", packet_type),
        }
    }

    /// Get the value to fill the reserved area with
    pub fn type_id(&self) -> u16 {
        use self::SrtControlPacket::*;

        match self {
            Reject => 0,
            HandshakeRequest(_) => 1,
            HandshakeResponse(_) => 2,
            KeyManagerRequest(_) => 3,
            KeyManagerResponse(_) => 4,
            StreamId => 5,
            Smoother => 6,
        }
    }
    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        use self::SrtControlPacket::*;

        match *self {
            HandshakeRequest(ref s) | HandshakeResponse(ref s) => {
                s.serialize(into);
            }
            KeyManagerRequest(ref k) | KeyManagerResponse(ref k) => {
                k.serialize(into);
            }
            _ => unimplemented!(),
        }
    }
    // size in 32-bit words
    pub fn size_words(&self) -> u16 {
        use self::SrtControlPacket::*;

        match self {
            // 3 32-bit words, version, flags, latency
            HandshakeRequest(_) | HandshakeResponse(_) => 3,
            // 4 32-bit words + salt + key + wrap [2]
            KeyManagerRequest(ref k) | KeyManagerResponse(ref k) => {
                4 + k.salt.len() as u16 / 4
                    + k.odd_key.as_ref().map(Vec::len).unwrap_or(0) as u16 / 4
                    + k.even_key.as_ref().map(Vec::len).unwrap_or(0) as u16 / 4
                    + 2
            }
            _ => unimplemented!(),
        }
    }
}

impl SrtHandshake {
    pub fn parse<T: Buf>(buf: &mut T) -> Result<SrtHandshake, Error> {
        if buf.remaining() < 12 {
            bail!("Unexpected EOF in SRT handshake packet");
        }

        let version = SrtVersion::parse(buf.get_u32());

        let shake_flags = buf.get_u32();
        let flags = match SrtShakeFlags::from_bits(shake_flags) {
            Some(i) => i,
            None => {
                warn!("Unrecognized SRT flags: 0b{:b}", shake_flags);
                SrtShakeFlags::from_bits_truncate(shake_flags)
            }
        };
        let peer_latency = buf.get_u16();
        let latency = buf.get_u16();

        Ok(SrtHandshake {
            version,
            flags,
            peer_latency: Duration::from_millis(u64::from(peer_latency)),
            latency: Duration::from_millis(u64::from(latency)),
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        into.put_u32(self.version.to_u32());
        into.put_u32(self.flags.bits());
        // upper 16 bits are peer latency
        into.put_u16(self.peer_latency.as_millis() as u16); // TODO: handle overflow

        // lower 16 is latency
        into.put_u16(self.latency.as_millis() as u16); // TODO: handle overflow
    }
}

impl SrtKeyMessage {
    pub fn parse(buf: &mut impl Buf) -> Result<SrtKeyMessage, Error> {
        // first 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |0|Vers |   PT  |             Sign              |    resv   |KF |

        // make sure there is enough data left in the buffer to at least get to the key flags and length, which tells us how long the packet will be
        // that's 4x32bit words
        if buf.remaining() < 4 * 4 {
            bail!("Not enough data for SrtKeyMessage");
        }

        let vers_pt = buf.get_u8();

        // make sure the first bit is zero
        if (vers_pt & 0b1000_0000) != 0 {
            bail!("First bit of SRT key message must be zero");
        }

        // upper 4 bits are version
        let version = vers_pt >> 4;

        if version != 1 {
            bail!("Invalid SRT key message version: {} must be 1.", version);
        }

        // lower 4 bits are pt
        let pt = vers_pt & 0b0000_1111;

        // next 16 bis are sign
        let sign = buf.get_u16();

        // next 6 bits is reserved, then two bits of KF
        let key_flags = buf.get_u8() & 0b0000_0011;

        // second 32-bit word: keki
        let keki = buf.get_u32();

        // third 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |    Cipher     |      Auth     |      SE       |     Resv1     |

        let cipher = CipherType::from_u8(buf.get_u8())?;
        let auth = buf.get_u8();
        let se = buf.get_u8();
        let _resv1 = buf.get_u8();

        // fourth 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |             Resv2             |     Slen/4    |     Klen/4    |

        let _resv2 = buf.get_u16();
        let salt_len = usize::from(buf.get_u8()) * 4;
        let key_len = usize::from(buf.get_u8()) * 4;

        // acceptable key lengths are 16, 24, and 32
        match key_len {
            // OK
            16 | 24 | 32 => {}
            // not
            e => {
                bail!("Invalid key length: {}. Expected 16, 24, or 32", e);
            }
        }

        // get the size of the packet to make sure that there is enough space

        // salt + keys (there's a 1 for each in key flags, it's already been anded with 0b11 so max is 2), wrap data is 8 long
        if buf.remaining() < salt_len + key_len * (key_flags.count_ones() as usize) + 8 {
            bail!("Not enough data for SrtKeyMessage");
        }

        // the reference implmentation converts the whole thing to network order (bit endian) (in 32-bit words)
        // so we need to make sure to do the same. Source:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/srtcore/crypto.cpp#L115

        // after this, is the salt
        let mut salt = vec![];
        for _ in 0..salt_len / 4 {
            salt.extend_from_slice(&buf.get_u32().to_be_bytes()[..]);
        }

        // then key[s]
        let even_key = if key_flags & 0b01 == 0b01 {
            let mut even_key = vec![];

            for _ in 0..key_len / 4 {
                even_key.extend_from_slice(&buf.get_u32().to_be_bytes()[..]);
            }
            Some(even_key)
        } else {
            None
        };

        let odd_key = if key_flags & 0b10 == 0b10 {
            let mut odd_key = vec![];

            for _ in 0..key_len / 4 {
                odd_key.extend_from_slice(&buf.get_u32().to_be_bytes()[..]);
            }
            Some(odd_key)
        } else {
            None
        };

        // finally, is the wrap data. it's 8 bytes. make sure to swap bytes correctly
        let mut wrap_data = [0; 8];

        wrap_data[..4].clone_from_slice(&buf.get_u32().to_be_bytes()[..]);
        wrap_data[4..].clone_from_slice(&buf.get_u32().to_be_bytes()[..]);

        Ok(SrtKeyMessage {
            pt,
            sign,
            keki,
            cipher,
            auth,
            se,
            salt,
            even_key,
            odd_key,
            wrap_data,
        })
    }

    fn serialize<T: BufMut>(&self, into: &mut T) {
        // first 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |0|Vers |   PT  |             Sign              |    resv   |KF |

        // version is 1
        into.put_u8(1 << 4 | self.pt);

        into.put_u16(self.sign);

        // rightmost bit of KF is even, other is odd
        into.put_u8(match (&self.odd_key, &self.even_key) {
            (Some(_), Some(_)) => 0b11,
            (Some(_), None) => 0b10,
            (None, Some(_)) => 0b01,
            (None, None) => panic!("Invalid key message: either even or odd key MUST be set"),
        });

        // second 32-bit word: keki
        into.put_u32(self.keki);

        // third 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |    Cipher     |      Auth     |      SE       |     Resv1     |
        into.put_u8(self.cipher as u8);
        into.put_u8(self.auth);
        into.put_u8(self.se);
        into.put_u8(0); // resv1

        // fourth 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |             Resv2             |     Slen/4    |     Klen/4    |
        into.put_u16(0); // resv2
        into.put_u8((self.salt.len() / 4) as u8);

        // this unwrap is okay because we already panic above if both are None
        let key_len = [&self.odd_key, &self.even_key]
            .iter()
            .filter_map(|&a| a.as_ref())
            .next()
            .unwrap()
            .len();
        into.put_u8((key_len / 4) as u8);

        // put the salt then key[s]
        into.put(&self.salt[..]);

        // the reference implmentation converts the whole thing to network order (big endian) (in 32-bit words)
        // so we need to make sure to do the same. Source:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/srtcore/crypto.cpp#L115

        if let Some(ref even) = self.even_key {
            for num in even[..].chunks(4) {
                into.put_u32(u32::from_be_bytes([num[0], num[1], num[2], num[3]]));
            }
        }
        if let Some(ref odd) = self.odd_key {
            for num in odd[..].chunks(4) {
                into.put_u32(u32::from_be_bytes([num[0], num[1], num[2], num[3]]));
            }
        }
        // put the wrap
        for num in self.wrap_data[..].chunks(4) {
            into.put_u32(u32::from_be_bytes([num[0], num[1], num[2], num[3]]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SrtControlPacket, SrtHandshake, SrtShakeFlags};
    use crate::packet::ControlTypes;
    use crate::{protocol::TimeStamp, ControlPacket, Packet, SocketID, SrtVersion};

    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn deser_ser_shake() {
        let handshake = Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(123_141),
            dest_sockid: SocketID(123),
            control_type: ControlTypes::Srt(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::empty(),
                peer_latency: Duration::from_millis(4000),
                latency: Duration::from_millis(3000),
            })),
        });

        let mut buf = Vec::new();
        handshake.serialize(&mut buf);

        let deserialized = Packet::parse(&mut Cursor::new(buf)).unwrap();

        assert_eq!(handshake, deserialized);
    }
}

impl CipherType {
    fn from_u8(from: u8) -> Result<CipherType, Error> {
        match from {
            0 => Ok(CipherType::None),
            1 => Ok(CipherType::ECB),
            2 => Ok(CipherType::CTR),
            3 => Ok(CipherType::CBC),
            e => bail!(
                "Unexpected cipher type in key message: {}. Must be 0, 1, 2, or 3",
                e
            ),
        }
    }
}
