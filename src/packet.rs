// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

use std::fmt::{self, Debug, Formatter};

use bytes::{Buf, BufMut};
use failure::{bail, Error};

mod codec;
mod control;
mod data;

pub use self::codec::PacketCodec;
pub use self::control::{
    AckControlInfo, CipherType, ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo,
    ShakeType, SocketType, SrtControlPacket, SrtHandshake, SrtKeyMessage, SrtShakeFlags,
};
pub use self::data::{DataPacket, PacketLocation};

use crate::protocol::TimeStamp;
use crate::SocketID;

/// Represents A UDT/SRT packet
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq)]
pub enum Packet {
    Data(DataPacket),
    Control(ControlPacket),
}
impl Packet {
    pub fn timestamp(&self) -> TimeStamp {
        match *self {
            Packet::Data(DataPacket { timestamp, .. })
            | Packet::Control(ControlPacket { timestamp, .. }) => timestamp,
        }
    }

    pub fn dest_sockid(&self) -> SocketID {
        match *self {
            Packet::Data(DataPacket { dest_sockid, .. })
            | Packet::Control(ControlPacket { dest_sockid, .. }) => dest_sockid,
        }
    }

    pub fn parse<T: Buf>(buf: &mut T) -> Result<Packet, Error> {
        // Buffer must be at least 16 bytes,
        // the length of a header packet
        if buf.remaining() < 16 {
            bail!("Packet not long enough to have a header");
        }

        // peek at the first byte to check if it's data or control
        let first = buf.bytes()[0];

        // Check if the first bit is one or zero;
        // if it's one it's a cotnrol packet,
        // if zero it's a data packet
        Ok(if (first & 0x80) == 0 {
            Packet::Data(DataPacket::parse(buf)?)
        } else {
            Packet::Control(ControlPacket::parse(buf)?)
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        match *self {
            Packet::Control(ref control) => {
                control.serialize(into);
            }
            Packet::Data(ref data) => {
                data.serialize(into);
            }
        }
    }
}
impl Debug for Packet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            Packet::Data(dp) => write!(f, "{:?}", dp),
            Packet::Control(cp) => write!(f, "{:?}", cp),
        }
    }
}
