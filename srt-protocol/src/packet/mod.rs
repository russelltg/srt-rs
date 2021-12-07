// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

mod control;
mod data;
mod error;
mod modular_num;
mod msg_number;
mod seq_number;
mod socket_id;
mod time;

pub use control::*;
pub use data::*;
pub use error::*;
pub use msg_number::*;
pub use seq_number::*;
pub use socket_id::*;
pub use time::*;

use std::{
    fmt::{self, Debug, Formatter},
    io,
    net::SocketAddr,
};

use bytes::{Buf, BufMut};

/// Represents A UDT/SRT packet
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Packet {
    Data(DataPacket),
    Control(ControlPacket),
}

impl Packet {
    const IPV4_HEADER_SIZE: u64 = 20;
    const UDP_HEADER_SIZE: u64 = 8;
    const SRT_HEADER_SIZE: u64 = 16;

    pub const HEADER_SIZE: u64 =
        Self::IPV4_HEADER_SIZE + Self::UDP_HEADER_SIZE + Self::SRT_HEADER_SIZE;

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

#[derive(Debug)]
pub enum ReceivePacketError {
    Parse(PacketParseError),
    Io(io::Error),
}

impl From<io::Error> for ReceivePacketError {
    fn from(error: io::Error) -> Self {
        ReceivePacketError::Io(error)
    }
}

impl From<PacketParseError> for ReceivePacketError {
    fn from(error: PacketParseError) -> Self {
        ReceivePacketError::Parse(error)
    }
}

impl fmt::Display for ReceivePacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ReceivePacketError::*;
        match self {
            Parse(e) => <PacketParseError as fmt::Display>::fmt(e, f),
            Io(e) => <io::Error as fmt::Display>::fmt(e, f),
        }
    }
}

impl std::error::Error for ReceivePacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self)
    }
}

// NOTE: Eq, PartialEq are only here to accommodate structural comparison in tests without losing
//  the ability to surface network errors for logging purposes, improve on this as needed, but don't
//  remove.
impl Eq for ReceivePacketError {}
impl PartialEq for ReceivePacketError {
    fn eq(&self, other: &Self) -> bool {
        use ReceivePacketError::*;
        match (self, other) {
            (Parse(s), Parse(o)) => s.eq(o),
            (Io(s), Io(o)) => s.kind().eq(&o.kind()) && s.raw_os_error().eq(&o.raw_os_error()),
            _ => false,
        }
    }
}

pub type ReceivePacketResult = Result<(Packet, SocketAddr), ReceivePacketError>;
