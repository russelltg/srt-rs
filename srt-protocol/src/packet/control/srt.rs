use std::{convert::TryFrom, time::Duration};

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use log::warn;

use crate::{PacketParseError, SrtVersion};
use core::fmt;
use std::fmt::Formatter;

/// The SRT-specific control packets
/// These are `Packet::Custom` types
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

    /// Stream identifier
    /// ID = 5
    StreamId(String),

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
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SrtKeyMessage {
    pub pt: PacketType, // TODO: i think this is always KeyingMaterial....
    pub key_flags: KeyFlags,
    pub keki: u32,
    pub cipher: CipherType,
    pub auth: Auth,
    pub salt: Vec<u8>,
    pub wrapped_keys: Vec<u8>,
}

impl fmt::Debug for SrtKeyMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtKeyMessage")
            .field("pt", &self.pt)
            .field("key_flags", &self.key_flags)
            .field("keki", &self.keki)
            .field("cipher", &self.cipher)
            .field("auth", &self.auth)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Auth {
    None = 0,
}

impl TryFrom<u8> for Auth {
    type Error = PacketParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Auth::None),
            e => Err(PacketParseError::BadAuth(e)),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StreamEncapsulation {
    Udp = 1,
    Srt = 2,
}

impl TryFrom<u8> for StreamEncapsulation {
    type Error = PacketParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => StreamEncapsulation::Udp,
            2 => StreamEncapsulation::Srt,
            e => return Err(PacketParseError::BadStreamEncapsulation(e)),
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PacketType {
    MediaStream = 1,
    KeyingMaterial = 2,
    // see htcryp_msg.h:43...
}

bitflags! {
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct KeyFlags : u8 {
        const EVEN = 0b01;
        const ODD = 0b10;
    }
}

impl TryFrom<u8> for PacketType {
    type Error = PacketParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::MediaStream),
            2 => Ok(PacketType::KeyingMaterial),
            err => Err(PacketParseError::BadKeyPacketType(err)),
        }
    }
}

/// from https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/haicrypt/hcrypt_msg.h#L121-L124
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum CipherType {
    None = 0,
    Ecb = 1,
    Ctr = 2,
    Cbc = 3,
}

/// The SRT handshake object
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SrtHandshake {
    /// The SRT version
    /// Serialized just as the u32 that SrtVersion serialized to
    pub version: SrtVersion,

    /// SRT connection init flags
    pub flags: SrtShakeFlags,

    /// The peer's TSBPD latency (latency to send at)
    /// This is serialized as the upper 16 bits of the third 32-bit word
    /// source: https://github.com/Haivision/srt/blob/4f7f2beb2e1e306111b9b11402049a90cb6d3787/srtcore/core.cpp#L1341-L1353
    pub send_latency: Duration,

    /// The TSBPD latency (latency to recv at)
    /// This is serialized as the lower 16 bits of the third 32-bit word
    /// see csrtcc.cpp:132 in the reference implementation
    pub recv_latency: Duration,
}

bitflags! {
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct SrtShakeFlags: u32 {
        /// Timestamp-based Packet delivery real-time data sender
        const TSBPDSND = 0x1;

        /// Timestamp-based Packet delivery real-time data receiver
        const TSBPDRCV = 0x2;

        /// HaiCrypt AES-128/192/256-CTR
        /// also represents if it supports the encryption flags in the data packet
        const HAICRYPT = 0x4;

        /// Drop real-time data packets too late to be processed in time
        const TLPKTDROP = 0x8;

        /// Periodic NAK report
        const NAKREPORT = 0x10;

        /// One bit in payload packet msgno is "retransmitted" flag
        const REXMITFLG = 0x20;

        /// This entity supports stream ID packets
        const STREAM = 0x40;

        /// Again not sure... TODO:
        const FILTERCAP = 0x80;

        // currently implemented flags
        const SUPPORTED = Self::TSBPDSND.bits | Self::TSBPDRCV.bits | Self::HAICRYPT.bits | Self::REXMITFLG.bits;
    }
}

impl SrtControlPacket {
    pub fn parse<T: Buf>(
        packet_type: u16,
        buf: &mut T,
    ) -> Result<SrtControlPacket, PacketParseError> {
        use self::SrtControlPacket::*;

        match packet_type {
            0 => Ok(Reject),
            1 => Ok(HandshakeRequest(SrtHandshake::parse(buf)?)),
            2 => Ok(HandshakeResponse(SrtHandshake::parse(buf)?)),
            3 => Ok(KeyManagerRequest(SrtKeyMessage::parse(buf)?)),
            4 => Ok(KeyManagerResponse(SrtKeyMessage::parse(buf)?)),
            5 => {
                // the stream id string is stored as 32-bit little endian words
                // https://tools.ietf.org/html/draft-sharabayko-mops-srt-01#section-3.2.1.3
                if buf.remaining() % 4 != 0 || buf.remaining() == 0 {
                    return Err(PacketParseError::NotEnoughData);
                }

                let mut bytes = Vec::with_capacity(buf.remaining());

                while buf.remaining() > 4 {
                    bytes.extend(&buf.get_u32_le().to_be_bytes());
                }

                // make sure to skip padding bytes if any for the last word
                match buf.get_u32_le().to_be_bytes() {
                    [a, 0, 0, 0] => bytes.push(a),
                    [a, b, 0, 0] => bytes.extend(&[a, b]),
                    [a, b, c, 0] => bytes.extend(&[a, b, c]),
                    _ => {}
                }

                match String::from_utf8(bytes) {
                    Ok(s) => Ok(StreamId(s)),
                    Err(e) => Err(PacketParseError::StreamTypeNotUtf8(e.utf8_error())),
                }
            }
            _ => Err(PacketParseError::UnsupportedSrtExtensionType(packet_type)),
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
            StreamId(_) => 5,
            Smoother => 6,
        }
    }
    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        use self::SrtControlPacket::*;

        match self {
            HandshakeRequest(s) | HandshakeResponse(s) => {
                s.serialize(into);
            }
            KeyManagerRequest(k) | KeyManagerResponse(k) => {
                k.serialize(into);
            }
            StreamId(sid) => {
                // the stream id string is stored as 32-bit little endian words
                // https://tools.ietf.org/html/draft-sharabayko-mops-srt-01#section-3.2.1.3
                let mut chunks = sid.as_bytes().chunks_exact(4);

                while let Some(&[a, b, c, d]) = chunks.next() {
                    into.put(&[d, c, b, a][..]);
                }

                // add padding bytes for the final word if needed
                match *chunks.remainder() {
                    [a, b, c] => into.put(&[0, c, b, a][..]),
                    [a, b] => into.put(&[0, 0, b, a][..]),
                    [a] => into.put(&[0, 0, 0, a][..]),
                    _ => {}
                }
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
                4 + k.salt.len() as u16 / 4 + k.wrapped_keys.len() as u16 / 4
            }
            StreamId(sid) => ((sid.len() + 3) / 4) as u16, // round up to nearest multiple of 4
            _ => unimplemented!(),
        }
    }
}

impl SrtHandshake {
    pub fn parse<T: Buf>(buf: &mut T) -> Result<SrtHandshake, PacketParseError> {
        if buf.remaining() < 12 {
            return Err(PacketParseError::NotEnoughData);
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
            send_latency: Duration::from_millis(u64::from(peer_latency)),
            recv_latency: Duration::from_millis(u64::from(latency)),
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        into.put_u32(self.version.to_u32());
        into.put_u32(self.flags.bits());
        // upper 16 bits are peer latency
        into.put_u16(self.send_latency.as_millis() as u16); // TODO: handle overflow

        // lower 16 is latency
        into.put_u16(self.recv_latency.as_millis() as u16); // TODO: handle overflow
    }
}

impl SrtKeyMessage {
    // from hcrypt_msg.h:39
    // also const traits aren't a thing yet, so u16::from can't be used
    const SIGN: u16 =
        ((b'H' - b'@') as u16) << 10 | ((b'A' - b'@') as u16) << 5 | (b'I' - b'@') as u16;

    pub fn parse(buf: &mut impl Buf) -> Result<SrtKeyMessage, PacketParseError> {
        // first 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |0|Vers |   PT  |             Sign              |    resv   |KF |

        // make sure there is enough data left in the buffer to at least get to the key flags and length, which tells us how long the packet will be
        // that's 4x32bit words
        if buf.remaining() < 4 * 4 {
            return Err(PacketParseError::NotEnoughData);
        }

        let vers_pt = buf.get_u8();

        // make sure the first bit is zero
        if (vers_pt & 0b1000_0000) != 0 {
            return Err(PacketParseError::BadSrtExtensionMessage);
        }

        // upper 4 bits are version
        let version = vers_pt >> 4;

        if version != 1 {
            return Err(PacketParseError::BadSrtExtensionMessage);
        }

        // lower 4 bits are pt
        let pt = PacketType::try_from(vers_pt & 0b0000_1111)?;

        // next 16 bis are sign
        let sign = buf.get_u16();

        if sign != Self::SIGN {
            return Err(PacketParseError::BadKeySign(sign));
        }

        // next 6 bits is reserved, then two bits of KF
        let key_flags = KeyFlags::from_bits_truncate(buf.get_u8() & 0b0000_0011);

        // second 32-bit word: keki
        let keki = buf.get_u32();

        // third 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |    Cipher     |      Auth     |      SE       |     Resv1     |

        let cipher = CipherType::try_from(buf.get_u8())?;
        let auth = Auth::try_from(buf.get_u8())?;
        let se = StreamEncapsulation::try_from(buf.get_u8())?;
        if se != StreamEncapsulation::Srt {
            return Err(PacketParseError::StreamEncapsulationNotSrt);
        }

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
            e => return Err(PacketParseError::BadCryptoLength(e as u32)),
        }

        // get the size of the packet to make sure that there is enough space

        // salt + keys (there's a 1 for each in key flags, it's already been anded with 0b11 so max is 2), wrap data is 8 long
        if buf.remaining() < salt_len + key_len * (key_flags.bits.count_ones() as usize) + 8 {
            return Err(PacketParseError::NotEnoughData);
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
        let mut wrapped_keys = vec![];

        for _ in 0..(key_len * key_flags.bits.count_ones() as usize + 8) / 4 {
            wrapped_keys.extend_from_slice(&buf.get_u32().to_be_bytes()[..]);
        }

        Ok(SrtKeyMessage {
            pt,
            key_flags,
            keki,
            cipher,
            auth,
            salt,
            wrapped_keys,
        })
    }

    fn serialize<T: BufMut>(&self, into: &mut T) {
        // first 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |0|Vers |   PT  |             Sign              |    resv   |KF |

        // version is 1
        into.put_u8(1 << 4 | self.pt as u8);

        into.put_u16(Self::SIGN);

        // rightmost bit of KF is even, other is odd
        into.put_u8(self.key_flags.bits);

        // second 32-bit word: keki
        into.put_u32(self.keki);

        // third 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |    Cipher     |      Auth     |      SE       |     Resv1     |
        into.put_u8(self.cipher as u8);
        into.put_u8(self.auth as u8);
        into.put_u8(StreamEncapsulation::Srt as u8);
        into.put_u8(0); // resv1

        // fourth 32-bit word:
        //
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+
        // |             Resv2             |     Slen/4    |     Klen/4    |
        into.put_u16(0); // resv2
        into.put_u8((self.salt.len() / 4) as u8);

        // this unwrap is okay because we already panic above if both are None
        let key_len = (self.wrapped_keys.len() - 8) / self.key_flags.bits.count_ones() as usize;
        into.put_u8((key_len / 4) as u8);

        // put the salt then key[s]
        into.put(&self.salt[..]);

        // the reference implmentation converts the whole thing to network order (big endian) (in 32-bit words)
        // so we need to make sure to do the same. Source:
        // https://github.com/Haivision/srt/blob/2ef4ef003c2006df1458de6d47fbe3d2338edf69/srtcore/crypto.cpp#L115

        for num in self.wrapped_keys[..].chunks(4) {
            into.put_u32(u32::from_be_bytes([num[0], num[1], num[2], num[3]]));
        }
    }
}

impl fmt::Debug for SrtControlPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtControlPacket::Reject => write!(f, "reject"),
            SrtControlPacket::HandshakeRequest(req) => write!(f, "hsreq={:?}", req),
            SrtControlPacket::HandshakeResponse(resp) => write!(f, "hsresp={:?}", resp),
            SrtControlPacket::KeyManagerRequest(req) => write!(f, "kmreq={:?}", req),
            SrtControlPacket::KeyManagerResponse(resp) => write!(f, "kmresp={:?}", resp),
            SrtControlPacket::StreamId(sid) => write!(f, "streamid={}", sid),
            SrtControlPacket::Smoother => write!(f, "smoother"),
        }
    }
}

impl TryFrom<u8> for CipherType {
    type Error = PacketParseError;
    fn try_from(from: u8) -> Result<CipherType, PacketParseError> {
        match from {
            0 => Ok(CipherType::None),
            1 => Ok(CipherType::Ecb),
            2 => Ok(CipherType::Ctr),
            3 => Ok(CipherType::Cbc),
            e => Err(PacketParseError::BadCipherKind(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SrtControlPacket, SrtHandshake, SrtKeyMessage, SrtShakeFlags};
    use crate::packet::{Auth, CipherType, ControlTypes, KeyFlags, PacketType};
    use crate::{protocol::TimeStamp, ControlPacket, Packet, SocketId, SrtVersion};

    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn deser_ser_shake() {
        let handshake = Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(123_141),
            dest_sockid: SocketId(123),
            control_type: ControlTypes::Srt(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: SrtVersion::CURRENT,
                flags: SrtShakeFlags::empty(),
                send_latency: Duration::from_millis(4000),
                recv_latency: Duration::from_millis(3000),
            })),
        });

        let mut buf = Vec::new();
        handshake.serialize(&mut buf);

        let deserialized = Packet::parse(&mut Cursor::new(buf), false).unwrap();

        assert_eq!(handshake, deserialized);
    }

    #[test]
    fn ser_deser_sid() {
        let sid = Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(123),
            dest_sockid: SocketId(1234),
            control_type: ControlTypes::Srt(SrtControlPacket::StreamId("Hellohelloheloo".into())),
        });

        let mut buf = Vec::new();
        sid.serialize(&mut buf);

        let deser = Packet::parse(&mut Cursor::new(buf), false).unwrap();

        assert_eq!(sid, deser);
    }

    #[test]
    fn srt_key_message_debug() {
        let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00\x85\x2c\x3c\xcd\x02\x65\x1a\x22";
        let wrapped = b"U\x06\xe9\xfd\xdfd\xf1'nr\xf4\xe9f\x81#(\xb7\xb5D\x19{\x9b\xcdx";

        let km = SrtKeyMessage {
            pt: PacketType::KeyingMaterial,
            key_flags: KeyFlags::EVEN,
            keki: 0,
            cipher: CipherType::Ctr,
            auth: Auth::None,
            salt: salt[..].into(),
            wrapped_keys: wrapped[..].into(),
        };

        assert_eq!(format!("{:?}", km), "SrtKeyMessage { pt: KeyingMaterial, key_flags: EVEN, keki: 0, cipher: Ctr, auth: None }")
    }
}
