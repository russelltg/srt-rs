use bytes::{Buf, BufMut};
use std::{
    io::{Error, ErrorKind, Result},
    time::Duration,
};

use SrtVersion;

/// The SRT-specific control packets
/// These are `Packet::Custom` types
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SrtControlPacket {
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
}

/// The SRT handshake object
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SrtHandshake {
    /// The SRT version
    /// Serialized just as the u32 that SrtVersion serialized to
    pub version: SrtVersion,

    /// SRT connection init flags
    pub flags: SrtShakeFlags,

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
        match packet_type {
            1 => Ok(SrtControlPacket::HandshakeRequest(SrtHandshake::parse(
                buf,
            )?)),
            2 => Ok(SrtControlPacket::HandshakeResponse(SrtHandshake::parse(
                buf,
            )?)),
            3 | 4 => unimplemented!(),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unrecognized custom packet type {}", packet_type),
            )),
        }
    }

    /// Get the value to fill the reserved area with
    pub fn reserved(&self) -> u16 {
        match *self {
            SrtControlPacket::HandshakeRequest(_) => 1,
            SrtControlPacket::HandshakeResponse(_) => 2,
            SrtControlPacket::KeyManagerRequest => 3,
            SrtControlPacket::KeyManagerResponse => 4,
        }
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) -> u16 {
        match *self {
            SrtControlPacket::HandshakeRequest(ref s) => {
                s.serialize(into);

                1
            }
            SrtControlPacket::HandshakeResponse(ref s) => {
                s.serialize(into);

                2
            }
            SrtControlPacket::KeyManagerRequest => 3,
            SrtControlPacket::KeyManagerResponse => 4,
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
        // the latency is the lower 16 bits, discard the upper 16
        buf.get_u16_be();

        let latency = buf.get_u16_be();

        Ok(SrtHandshake {
            version,
            flags,
            latency: Duration::from_millis(u64::from(latency)),
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        into.put_u32_be(self.version.to_u32());
        into.put_u32_be(self.flags.bits());
        // upper 16 bits are all zero
        into.put_u16_be(0);
        // lower 16 is latency
        into.put_u16_be(
            (self.latency.subsec_millis()) as u16 + self.latency.as_secs() as u16 * 1_000,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{SrtControlPacket, SrtHandshake, SrtShakeFlags};
    use packet::ControlTypes;
    use srt_version;
    use {ControlPacket, Packet, SocketID};

    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn deser_ser_shake() {
        let handshake = Packet::Control(ControlPacket {
            timestamp: 123141,
            dest_sockid: SocketID(123),
            control_type: ControlTypes::Srt(SrtControlPacket::HandshakeRequest(SrtHandshake {
                version: srt_version::CURRENT,
                flags: SrtShakeFlags::empty(),
                latency: Duration::from_millis(3000),
            })),
        });

        let mut buf = Vec::new();
        handshake.serialize(&mut buf);

        let deserialized = Packet::parse(&mut Cursor::new(buf)).unwrap();

        assert_eq!(handshake, deserialized);
    }
}
