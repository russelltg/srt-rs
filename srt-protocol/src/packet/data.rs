use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes};

use std::cmp::min;
use std::{convert::TryFrom, fmt};

use super::PacketParseError;
use crate::protocol::TimeStamp;
use crate::{MsgNumber, SeqNumber, SocketId};

/// A UDT packet carrying data
///
/// ```ignore,
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |0|                     Packet Sequence Number                  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |FF |O|K K|R|               Message Number                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          Time Stamp                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    Destination Socket ID                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// (from <https://tools.ietf.org/html/draft-gg-udt-03>)
#[derive(Clone, PartialEq, Eq)]
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

    /// row 2 bits 4+5, which key it's encrypted with, if it is
    pub encryption: DataEncryption,

    // row 2 bit 6, if the packet was retransmitteed
    pub retransmitted: bool,

    /// The message number, is the ID of the message being passed
    /// Represented by the final 26 bits of the third row
    /// It's only 26 bits long, so it's wrapped after 2^26 - 1
    pub message_number: MsgNumber,

    /// The timestamp, relative to when the connection was created.
    pub timestamp: TimeStamp,

    /// The dest socket id, used for UDP multiplexing
    pub dest_sockid: SocketId,

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
        const ONLY = Self::FIRST.bits | Self::LAST.bits;
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum DataEncryption {
    None = 0b0000_0000,
    Even = 0b0000_1000,
    Odd = 0b0001_0000,
}

impl DataPacket {
    pub fn parse(buf: &mut impl Buf) -> Result<DataPacket, PacketParseError> {
        // get the sequence number, which is the last 31 bits of the header
        let seq_number = SeqNumber::new_truncate(buf.get_u32());

        let second_word_first_byte = buf.get_u32();
        let [swb1, _, _, _] = second_word_first_byte.to_be_bytes();

        // the first two bits of the second line (second_line >> 24) is the location
        let message_loc = PacketLocation::from_bits_truncate(swb1);
        let encryption = DataEncryption::try_from(swb1)?;
        let retransmitted = (swb1 >> 2) & 1 == 1;

        // in order delivery is the third bit
        let in_order_delivery = (swb1 & 0b0010_0000) != 0;

        let message_number = MsgNumber::new_truncate(second_word_first_byte);
        let timestamp = TimeStamp::from_micros(buf.get_u32());
        let dest_sockid = SocketId(buf.get_u32());

        Ok(DataPacket {
            seq_number,
            message_loc,
            in_order_delivery,
            encryption,
            retransmitted,
            message_number,
            timestamp,
            dest_sockid,
            payload: Buf::copy_to_bytes(buf, buf.remaining()),
        })
    }

    pub fn serialize(&self, into: &mut impl BufMut) {
        assert!(self.seq_number.as_raw() & (1 << 31) == 0);

        into.put_u32(self.seq_number.as_raw());

        // the format is first two bits are the message location, third is in order delivery, and the rest is message number
        // message number is guaranteed to have it's first three bits as zero
        into.put_u32(
            self.message_number.as_raw()
                | ((u32::from(
                    self.message_loc.bits() // first 2 bits
                        | (self.in_order_delivery as u8) << 5 // 3rd bit
                        | self.encryption as u8 // 4th-5th bits
                        | (self.retransmitted as u8) << 2, // 6th bit
                )) << 24),
        );
        into.put_u32(self.timestamp.as_micros());
        into.put_u32(self.dest_sockid.0);
        into.put(&self.payload[..]);
    }
}

impl TryFrom<u8> for DataEncryption {
    type Error = PacketParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value & 0b0001_1000 {
            0b0000_0000 => DataEncryption::None,
            0b0000_1000 => DataEncryption::Even,
            0b0001_0000 => DataEncryption::Odd,
            e => return Err(PacketParseError::BadDataEncryption(e)),
        })
    }
}

impl fmt::Debug for DataPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{{DATA sn={} loc={:?} enc={:?} re={:?} msgno={} ts={:.4} dst={:?} payload=[len={}, start={:?}]}}",
            self.seq_number.0,
            self.message_loc,
            self.encryption,
            self.retransmitted,
            self.message_number.0,
            self.timestamp.as_secs_f64(),
            self.dest_sockid,
            self.payload.len(),
            self.payload.slice(..min(8, self.payload.len())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    proptest! {
        #[test]
        fn data_enc(i: u8) {
            match DataEncryption::try_from(i) {
                Err(PacketParseError::BadDataEncryption(e)) => {
                    assert_eq!(i & 0b0001_1000, e);
                    assert_eq!(e, 0b0001_1000);
                }
                Err(e) => panic!("{}", e),
                Ok(de) => {
                    assert_eq!(de as u8, i & 0b0001_1000);
                }
            }

        }
        #[test]
        fn test_datapacket(message_loc: u8, enc in 0u8..3u8, retransmitted: bool, in_order_delivery: bool) {
            let message_loc = PacketLocation::from_bits_truncate(message_loc);
            let encryption = DataEncryption::try_from(enc << 3).unwrap();
            let dp = DataPacket {
                seq_number: SeqNumber::new_truncate(123),
                message_loc,
                in_order_delivery,
                encryption,
                retransmitted,
                message_number: MsgNumber::new_truncate(123),
                timestamp: TimeStamp::from_micros(0),
                dest_sockid: SocketId(0),
                payload: Bytes::new(),
            };
            let mut v = vec![];
            dp.serialize(&mut v);
            let dp2 = DataPacket::parse(&mut Cursor::new(&v)).unwrap();

            assert_eq!(dp, dp2);

            let mut v2 = vec![];
            dp2.serialize(&mut v2);
            assert_eq!(v, v2);
        }
    }
}
