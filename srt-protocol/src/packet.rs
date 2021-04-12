// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

use std::fmt::{self, Debug, Formatter};

use bytes::{Buf, BufMut};

mod control;
mod data;
mod error;

pub use self::control::*;
pub use self::data::*;
pub use error::PacketParseError;

use crate::protocol::TimeStamp;
use crate::SocketId;

/// Represents A UDT/SRT packet
#[derive(Clone, PartialEq, Eq)]
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

    pub fn dest_sockid(&self) -> SocketId {
        match *self {
            Packet::Data(DataPacket { dest_sockid, .. })
            | Packet::Control(ControlPacket { dest_sockid, .. }) => dest_sockid,
        }
    }

    pub fn data(&self) -> Option<&DataPacket> {
        if let Packet::Data(d) = self {
            Some(d)
        } else {
            None
        }
    }

    pub fn control(&self) -> Option<&ControlPacket> {
        if let Packet::Control(c) = self {
            Some(c)
        } else {
            None
        }
    }

    pub fn parse<T: Buf>(buf: &mut T, is_ipv6: bool) -> Result<Packet, PacketParseError> {
        // Buffer must be at least 16 bytes,
        // the length of a header packet
        if buf.remaining() < 16 {
            return Err(PacketParseError::NotEnoughData);
        }

        // peek at the first byte to check if it's data or control
        let first = buf.chunk()[0];

        // Check if the first bit is one or zero;
        // if it's one it's a cotnrol packet,
        // if zero it's a data packet
        Ok(if (first & 0x80) == 0 {
            Packet::Data(DataPacket::parse(buf)?)
        } else {
            Packet::Control(ControlPacket::parse(buf, is_ipv6)?)
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

impl From<DataPacket> for Packet {
    fn from(dp: DataPacket) -> Self {
        Packet::Data(dp)
    }
}

impl From<ControlPacket> for Packet {
    fn from(cp: ControlPacket) -> Self {
        Packet::Control(cp)
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
