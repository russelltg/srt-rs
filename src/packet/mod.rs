// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

mod control;
mod data;

pub use self::control::{
    ControlPacket, ControlTypes, HandshakeControlInfo, ShakeType, SocketType, SrtControlPacket,
    SrtHandshake, SrtShakeFlags,
};
pub use self::data::{DataPacket, PacketLocation};

use {
    bytes::{Buf, BufMut}, failure::Error,
};

/// Represents A UDT/SRT packet
#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Data(DataPacket),
    Control(ControlPacket),
}
impl Packet {
    // TODO: should this be u32?
    pub fn timestamp(&self) -> i32 {
        match *self {
            Packet::Data(DataPacket { timestamp, .. })
            | Packet::Control(ControlPacket { timestamp, .. }) => timestamp,
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
