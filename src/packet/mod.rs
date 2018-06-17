// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

mod data;
mod control;

pub use self::data::{DataPacket, PacketLocationOrder};
pub use self::control::{ControlPacket, ConnectionType, ControlTypes};

use {
    bytes::{Buf, BufMut, Bytes}, failure::Error, std::io::Cursor, std::net::{IpAddr, Ipv4Addr},
    SeqNumber, SocketID, MsgNumber,
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
            Packet::Data (DataPacket{ timestamp, .. }) | Packet::Control(ControlPacket { timestamp, .. }) => timestamp,
        }
    }

    pub fn parse<T: Buf>(mut buf: T) -> Result<Packet, Error> {
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
        if (first & 0x80) == 0 {
			Packet::Data(DataPacket::parse(buf))
        } else {
			Packet::Control(ControlPacket::parse(buf))
        }
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        match *self {
            Packet::Control(control) => {
					control.serialize(into);
                            }
            Packet::Data (data) => {
				data.serialize(into);
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::{
        AckControlInfo, ConnectionType, ControlTypes, HandshakeControlInfo, Packet, PacketLocation,
        SocketType,
    };
    use std::io::Cursor;
    use {SeqNumber, SocketID};

    #[test]
    fn packet_location_from_i32_test() {
        assert_eq!(PacketLocation::from_i32(0b10 << 30), PacketLocation::First);
        assert_eq!(
            PacketLocation::from_i32(!(0b01 << 30)),
            PacketLocation::First
        );
        assert_eq!(
            PacketLocation::from_i32(0b101010101110 << 20),
            PacketLocation::First
        );

        assert_eq!(PacketLocation::from_i32(0b00), PacketLocation::Middle);
        assert_eq!(
            PacketLocation::from_i32(!(0b11 << 30)),
            PacketLocation::Middle
        );
        assert_eq!(
            PacketLocation::from_i32(0b001010101110 << 20),
            PacketLocation::Middle
        );

        assert_eq!(PacketLocation::from_i32(0b01 << 30), PacketLocation::Last);
        assert_eq!(
            PacketLocation::from_i32(!(0b10 << 30)),
            PacketLocation::Last
        );
        assert_eq!(
            PacketLocation::from_i32(0b011100101110 << 20),
            PacketLocation::Last
        );

        assert_eq!(PacketLocation::from_i32(0b11 << 30), PacketLocation::Only);
        assert_eq!(
            PacketLocation::from_i32(!(0b00 << 30)),
            PacketLocation::Only
        );
        assert_eq!(
            PacketLocation::from_i32(0b110100101110 << 20),
            PacketLocation::Only
        );
    }

    #[test]
    fn packet_location_as_i32_test() {
        assert_eq!(PacketLocation::First.as_i32(), 0b10 << 30);
        assert_eq!(PacketLocation::Middle.as_i32(), 0b0);
        assert_eq!(PacketLocation::Last.as_i32(), 0b01 << 30);
        assert_eq!(PacketLocation::Only.as_i32(), 0b11 << 30);
    }

    #[test]
    fn handshake_ser_des_test() {
        let pack = Packet::Control {
            timestamp: 0,
            dest_sockid: SocketID(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                udt_version: 4,
                sock_type: SocketType::Datagram,
                init_seq_num: SeqNumber::new(1827131),
                max_packet_size: 1500,
                max_flow_size: 25600,
                connection_type: ConnectionType::Regular,
                socket_id: SocketID(1231),
                syn_cookie: 0,
                peer_addr: "127.0.0.1".parse().unwrap(),
            }),
        };

        let mut buf = vec![];
        pack.serialize(&mut buf);

        let des = Packet::parse(Cursor::new(buf)).unwrap();

        assert_eq!(pack, des);
    }

    #[test]
    fn ack_ser_des_test() {
        let pack = Packet::Control {
            timestamp: 113703,
            dest_sockid: SocketID(2453706529),
            control_type: ControlTypes::Ack(
                1,
                AckControlInfo {
                    ack_number: SeqNumber::new(282049186),
                    rtt: Some(10002),
                    rtt_variance: Some(1000),
                    buffer_available: Some(1314),
                    packet_recv_rate: Some(0),
                    est_link_cap: Some(0),
                },
            ),
        };

        let mut buf = vec![];
        pack.serialize(&mut buf);

        println!("len={}, {:x?}", buf.len(), &buf);

        let des = Packet::parse(Cursor::new(buf)).unwrap();

        assert_eq!(pack, des);
    }
}
