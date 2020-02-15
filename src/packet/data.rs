use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes};
use failure::Error;

use std::cmp::min;
use std::fmt;

use crate::{MsgNumber, SeqNumber, SocketID};

/// A UDT packet carrying data
///
/// ```ignore,
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |0|                     Packet Sequence Number                  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |FF |O|                     Message Number                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          Time Stamp                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    Destination Socket ID                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// (from <https://tools.ietf.org/html/draft-gg-udt-03>)
#[derive(Clone, PartialEq)]
pub struct DataPacket {
    /// The sequence number is packet based, so if packet n has
    /// sequence number `i`, the next would have `i + 1`

    /// Represented by a 31 bit unsigned integer, so
    /// Sequence number is wrapped after it recahed 2^31 - 1
    pub seq_number: SeqNumber,

    /// Message location and delivery order
    /// Represented by the first two bits in the second row of 4 bytes
    pub message_loc: PacketLocation,

    /// In order delivery, the third bit in the second row of 4 bytes
    pub in_order_delivery: bool,

    /// The message number, is the ID of the message being passed
    /// Represented by the final 29 bits of the third row
    /// It's only 29 bits long, so it's wrapped after 2^29 - 1
    pub message_number: MsgNumber,

    /// The timestamp, relative to when the connection was created.
    pub timestamp: i32,

    /// The dest socket id, used for UDP multiplexing
    pub dest_sockid: SocketID,

    /// The rest of the packet, the payload
    pub payload: Bytes,
}

bitflags! {
    /// Signifies the packet location in a message for a data packet
    /// The bitflag just represents the first byte in the second line
    /// FIRST | LAST means it's the only one
    /// FIRST means it's the beginning of a longer message
    /// 0 means it's the middle of a longer message
    pub struct PacketLocation: u8 {
        const MIDDLE   = 0b0000_0000;
        const FIRST    = 0b1000_0000;
        const LAST     = 0b0100_0000;
    }
}

impl DataPacket {
    pub fn parse(buf: &mut impl Buf) -> Result<DataPacket, Error> {
        // get the sequence number, which is the last 31 bits of the header
        let seq_number = SeqNumber::new_truncate(buf.get_u32());

        // the first two bits of the second line (second_line >> 24) is the location
        let message_loc = PacketLocation::from_bits_truncate(buf.bytes()[0]);

        // in order delivery is the third bit
        let in_order_delivery = (buf.bytes()[0] & 0b0010_0000) != 0;

        let message_number = MsgNumber::new_truncate(buf.get_u32());
        let timestamp = buf.get_i32();
        let dest_sockid = SocketID(buf.get_u32());

        Ok(DataPacket {
            seq_number,
            message_loc,
            in_order_delivery,
            message_number,
            timestamp,
            dest_sockid,
            payload: buf.to_bytes(),
        })
    }

    pub fn serialize(&self, into: &mut impl BufMut) {
        assert!(self.seq_number.as_raw() & (1 << 31) == 0);

        into.put_u32(self.seq_number.as_raw());

        // the format is first two bits are the message location, third is in order delivery, and the rest is message number
        // message number is garunteed have it's first three bits as zero
        into.put_u32(
            self.message_number.as_raw()
                | ((u32::from(self.message_loc.bits() | (self.in_order_delivery as u8) << 5))
                    << 24),
        );
        into.put_i32(self.timestamp);
        into.put_u32(self.dest_sockid.0);
        into.put(&self.payload[..]);
    }
}

impl fmt::Debug for DataPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{{DATA sn={} loc={:?} msgno={} ts={:.4} dst={:X} payload=[len={}, start={:?}]}}",
            self.seq_number.0,
            self.message_loc,
            self.message_number.0,
            self.timestamp as f64 / 1e6,
            self.dest_sockid.0,
            self.payload.len(),
            self.payload.slice(..min(8, self.payload.len())),
        )
    }
}
