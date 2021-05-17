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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            Packet::Control(ControlPacket {
                control_type: ControlTypes::Handshake(_),
                ..
            })
        )
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

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::Packet;

    const FUZZ_VECTORS: &[&str] = &[
        "ffff000535012fffff2d29ff00ffffff",
        "8000200523ffffff00012101000000000000000500000000000000000000\
            000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000003100014100d9\
            0000001a000000000001000000000035000000008000000051ffff000551\
            5151515151515101015151ffc80127110101ffff00ff0a01000000000000\
            00ffff",
    ];

    // tests from fuzzing
    #[test]
    fn fuzz() {
        for v in FUZZ_VECTORS {
            let data = hex::decode(v).unwrap();
            let _ = Packet::parse(&mut Cursor::new(data), true);
        }
    }
}
