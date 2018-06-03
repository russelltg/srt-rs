use bytes::{Buf, BufMut};
use std::{
    io::{Error, ErrorKind, Result}, time::Duration,
};

use SrtVersion;

/// The SRT-specific control packets
/// These are `Packet::Custom` types
pub enum SrtControlPacket {
    /// SRT handshake request
    /// ID = 1
    HandshakeRequest(SrtHandshake),

    /// SRT handshake response
    /// ID = 2
    HandshakeResponse(SrtHandshake),
    // TODO: there are more, SRT_CMD_KMREQ and SRT_CMD_KMRSP
}

/// The SRT handshake object
/// It's just these three fields encoded as i32's
pub struct SrtHandshake {
    /// The SRT version
    pub version: SrtVersion,

    /// SRT connection init flags
    pub flags: SrtShakeFlags,

    /// The TSBPD latency
    pub latency: Duration,
}

bitflags! {
    pub struct SrtShakeFlags: i32 {
        /// Timestamp-based Packet delivery real-time data sender
        const TSBPDSND = 0x00000001;

        /// Timestamp-based Packet delivery real-time data receiver
        const TSBPDRCV = 0x00000002;

        /// HaiCrypt AES-128/192/256-CTR
        const HAICRYPT = 0x00000004;

        /// Drop real-time data packets too late to be processed in time
        const TLPKTDROP = 0x00000008;

        /// Periodic NAK report
        const NAKREPORT = 0x00000010;

        /// One bit in payload packet msgno is "retransmitted" flag
        const REXMITFLG = 0x00000020;
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

        let version = SrtVersion::parse(buf.get_i32_be());
        let flags = match SrtShakeFlags::from_bits(buf.get_i32_be()) {
            Some(i) => i,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid combination of SRT flags",
                ))
            }
        };
        let latency = buf.get_i32_be();

        Ok(SrtHandshake {
            version,
            flags,
            latency: Duration::new(0, latency as u32 * 1_000_000), // latency is in ms, convert to ns
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        into.put_i32_be(self.version.to_i32());
        into.put_i32_be(self.flags.bits());
        into.put_i32_be(
            (self.latency.subsec_nanos() / 1_000_000) as i32
                + self.latency.as_secs() as i32 * 1_000,
        );
    }
}
