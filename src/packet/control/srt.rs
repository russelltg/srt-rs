use std::io::{Error, ErrorKind, Result};
use std::time::Duration;

use bitflags::bitflags;
use bytes::{Buf, BufMut};

use crate::SrtVersion;

/// The SRT-specific control packets
/// These are `Packet::Custom` types
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    KeyManagerRequest,

    /// Key manager response
    /// ID = 4
    KeyManagerResponse,

    /// StreamID(?) // TODO: research
    /// ID = 5
    StreamId,

    /// Smoother? // TODO: research
    /// ID = 6
    Smoother,
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
    }
}

impl SrtControlPacket {
    pub fn parse<T: Buf>(packet_type: u16, buf: &mut T) -> Result<SrtControlPacket> {
        use self::SrtControlPacket::*;

        match packet_type {
            0 => Ok(Reject),
            1 => Ok(HandshakeRequest(SrtHandshake::parse(buf)?)),
            2 => Ok(HandshakeResponse(SrtHandshake::parse(buf)?)),
            3 | 4 => unimplemented!(),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unrecognized custom packet type {}", packet_type),
            )),
        }
    }

    /// Get the value to fill the reserved area with
    pub fn type_id(&self) -> u16 {
        use self::SrtControlPacket::*;

        match self {
            Reject => 0,
            HandshakeRequest(_) => 1,
            HandshakeResponse(_) => 2,
            KeyManagerRequest => 3,
            KeyManagerResponse => 4,
            StreamId => 5,
            Smoother => 6,
        }
    }
    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        use self::SrtControlPacket::*;

        match *self {
            HandshakeRequest(ref s) => {
                s.serialize(into);
            }
            HandshakeResponse(ref s) => {
                s.serialize(into);
            }
            _ => unimplemented!(),
        }
    }
}

impl SrtHandshake {
    pub fn parse<T: Buf>(buf: &mut T) -> Result<SrtHandshake> {
        if buf.remaining() < 12 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Unexpected EOF in SRT handshake packet",
            ));
        }

        let version = SrtVersion::parse(buf.get_u32_be());
        let flags = match SrtShakeFlags::from_bits(buf.get_u32_be()) {
            Some(i) => i,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid combination of SRT flags",
                ))
            }
        };
        let peer_latency = buf.get_u16_be();
        let latency = buf.get_u16_be();

        Ok(SrtHandshake {
            version,
            flags,
            peer_latency: Duration::from_millis(u64::from(peer_latency)),
            latency: Duration::from_millis(u64::from(latency)),
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        into.put_u32_be(self.version.to_u32());
        into.put_u32_be(self.flags.bits());
        // upper 16 bits are peer latency
        into.put_u16_be(
            self.peer_latency.subsec_millis() as u16 + self.peer_latency.as_secs() as u16 * 1_000,
        );
        // lower 16 is latency
        into.put_u16_be(
            self.latency.subsec_millis() as u16 + self.latency.as_secs() as u16 * 1_000,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{SrtControlPacket, SrtHandshake, SrtShakeFlags};
    use crate::packet::ControlTypes;
    use crate::{ControlPacket, Packet, SocketID, SrtVersion};

    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn deser_ser_shake() {
        let handshake = Packet::Control(ControlPacket {
            timestamp: 123_141,
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
