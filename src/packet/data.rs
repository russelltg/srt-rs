use {SeqNumber, MsgNumber, SocketID, bytes::Bytes};

/// A UDT packet carrying data
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
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// (from <https://tools.ietf.org/html/draft-gg-udt-03>)
pub struct DataPacket {
        /// The sequence number is packet based, so if packet n has
        /// sequence number `i`, the next would have `i + 1`

        /// Represented by a 31 bit unsigned integer, so
        /// Sequence number is wrapped after it recahed 2^31 - 1
        seq_number: SeqNumber,

        /// Message location and delivery order
        /// Represented by the first three bits in the second row of 4 bytes
        message_loc_order: PacketLocationOrder,

        /// The message number, is the ID of the message being passed
        /// Represented by the final 29 bits of the third row
        /// It's only 29 bits long, so it's wrapped after 2^29 - 1
        message_number: MsgNumber,

        /// The timestamp, relative to when the connection was created.
        timestamp: i32,

        /// The dest socket id, used for UDP multiplexing
        dest_sockid: SocketID,

        /// The rest of the packet, the payload
        payload: Bytes,
}


/// Signifies the packet location in a message for a data packet and the delivery order
/// The bitflag just represents the first byte in the second line
/// FIRST | LAST means it's the only one
/// FIRST means it's the beginning of a longer message
/// LAST means it's the end of a longer message
/// 0 means it's the middle of a longer message
bitflags! {
	pub struct PacketLocationOrder: u8 {
		const FIRST    = 0b10000000;
		const LAST     = 0x01000000;
		const ORDERED  = 0x00100000;
	}
}

impl DataPacket {
	fn parse<T: Buf>(mut buf: T) -> Result<DataPacket, Error> {

           // get the sequence number, which is the last 31 bits of the header
           let seq_number = SeqNumber::new(buf.get_u32_be());

		// the first byte (second_line >> 24) is the location and order
           let message_loc_order = PacketLocationOrder::from_bits_truncate(buf.bytes()[0]);

           let message_number = MsgNumber::new(buf.get_u32_be());
           let timestamp = buf.get_i32_be();
           let dest_sockid = SocketID(buf.get_u32_be());

           Ok(DataPacket {
               seq_number,
               message_loc_order,
               message_number,
               timestamp,
               dest_sockid,
               payload: buf.collect(),
          })

	}

	fn serialize<T: BufMut>(&self, into: &mut T) {
		assert!(self.seq_number.as_raw() & (1 << 31) == 0);

		into.put_u32_be(self.seq_number.as_raw());
		into.put_i32_be(
			self.message_number.as_raw() | ((self.message_loc_order.bits() as u32) << 24)
		);
		into.put_i32_be(*timestamp);
		into.put_u32_be(dest_sockid.0);
		into.put(payload);
	}
}

