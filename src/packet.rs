// Packet structures
// see https://tools.ietf.org/html/draft-gg-udt-03#page-5

use bytes::{Buf, BufMut, Bytes};

use std::io::{Cursor, Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr};

use {SeqNumber, SocketID};

/// Represents A UDT/SRT packet
#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
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
    Data {
        /// The sequence number is packet based, so if packet n has
        /// sequence number `i`, the next would have `i + 1`

        /// Represented by a 31 bit unsigned integer, so
        /// Sequence number is wrapped after it recahed 2^31 - 1
        seq_number: SeqNumber,

        /// Message location
        /// Represented by the first two bits in the second row of 4 bytes
        message_loc: PacketLocation,

        /// Should this message be delivered in order?
        /// Represented by the third bit in the second row
        in_order_delivery: bool,

        /// The message number, is the ID of the message being passed
        /// Represented by the final 29 bits of the third row
        /// It's only 29 bits long, so it's wrapped after 2^29 - 1
        message_number: i32,

        /// The timestamp, relative to when the connection was created.
        timestamp: i32,

        /// The dest socket id, used for UDP multiplexing
        dest_sockid: SocketID,

        /// The rest of the packet, the payload
        payload: Bytes,
    },

    /// A UDP packet carrying control information
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |1|             Type            |            Reserved           |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |     |                    Additional Info                      |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                            Time Stamp                         |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                    Destination Socket ID                      |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                                                               |
    ///  ~                 Control Information Field                     ~
    ///  |                                                               |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// (from <https://tools.ietf.org/html/draft-gg-udt-03#page-5>)
    Control {
        /// The timestamp, relative to the socket start time
        timestamp: i32,

        /// The dest socket ID, used for multiplexing
        dest_sockid: SocketID,

        /// The extra data
        control_type: ControlTypes,
    },
}

impl Packet {
    pub fn seq_number(&self) -> Option<SeqNumber> {
        if let Packet::Data { seq_number, .. } = *self {
            Some(seq_number)
        } else {
            None
        }
    }
    pub fn payload(&self) -> Option<Bytes> {
        if let Packet::Data { ref payload, .. } = *self {
            Some(payload.clone())
        } else {
            None
        }
    }
    pub fn packet_location(&self) -> Option<PacketLocation> {
        if let Packet::Data { message_loc, .. } = *self {
            Some(message_loc)
        } else {
            None
        }
    }
    pub fn message_number(&self) -> Option<i32> {
        if let Packet::Data { message_number, .. } = *self {
            Some(message_number)
        } else {
            None
        }
    }
}

/// Signifies the packet location in a message for a data packet
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PacketLocation {
    /// The first packet in a message, 10 in the FF location
    First,

    /// Somewhere in the middle, 00 in the FF location
    Middle,

    /// The last packet in a message, 01 in the FF location
    Last,

    /// The only packet in a message, 11 in the FF location
    Only,
}

impl PacketLocation {
    // Takes the second line of a data packet and gives the packet location in the message
    fn from_i32(from: i32) -> PacketLocation {
        match from {
            x if (x & (0b11 << 30)) == (0b10 << 30) => PacketLocation::First,
            x if (x & (0b11 << 30)) == (0b01 << 30) => PacketLocation::Last,
            x if (x & (0b11 << 30)) == (0b11 << 30) => PacketLocation::Only,
            _ => PacketLocation::Middle,
        }
    }

    fn to_i32(&self) -> i32 {
        match *self {
            PacketLocation::First => 0b10 << 30,
            PacketLocation::Middle => 0b00,
            PacketLocation::Last => 0b01 << 30,
            PacketLocation::Only => 0b11 << 30,
        }
    }
}

/// The different kind of control packets
#[derive(Debug, Clone, PartialEq)]
pub enum ControlTypes {
    /// The control packet for initiating connections, type 0x0
    /// Does not use Additional Info
    Handshake(HandshakeControlInfo),

    /// To keep a connection alive
    /// Does not use Additional Info or Control Info, type 0x1
    KeepAlive,

    /// ACK packet, type 0x2
    /// Additional Info (the i32) is the ACK sequence number
    Ack(i32, AckControlInfo),

    /// NAK packet, type 0x3
    /// Additional Info isn't used
    Nak(NakControlInfo),

    /// Shutdown packet, type 0x5
    Shutdown,

    /// Acknowledgement of Acknowledgement (ACK2) 0x6
    /// Additional Info (the i32) is the ACK sequence number to acknowldege
    Ack2(i32),

    /// Drop request, type 0x7
    /// Additional Info (the i32) is the message ID to drop
    DropRequest(i32, DropRequestControlInfo),

    /// Custom packets
    /// Mainly used for special SRT handshake packets
    /// The i32 is the second 16 bits of the first line, which is reserved for this use.
    Custom(u16, Bytes),
}

impl ControlTypes {
    /// Deserialize a control info
    /// * `packet_type` - The packet ID byte, the second byte in the first row
    /// * `reserved` - the second 16 bytes of the first row, reserved for custom packets
    fn deserialize<T: Buf>(
        packet_type: u16,
        reserved: u16,
        extra_info: i32,
        mut buf: T,
    ) -> Result<ControlTypes> {
        match packet_type {
            0x0 => {
                // Handshake

                let udt_version = buf.get_i32_be();
                let sock_type = SocketType::from_i32(buf.get_i32_be())?;
                let init_seq_num = SeqNumber::new(buf.get_i32_be());
                let max_packet_size = buf.get_i32_be();
                let max_flow_size = buf.get_i32_be();
                let connection_type = ConnectionType::from_i32(buf.get_i32_be())?;
                let socket_id = SocketID(buf.get_i32_be());
                let syn_cookie = buf.get_i32_be();

                // get the IP
                let mut ip_buf: [u8; 16] = [0; 16];
                buf.copy_to_slice(&mut ip_buf);

                // TODO: this is probably really wrong, so fix it
                let peer_addr = if ip_buf[4..] == b"\0\0\0\0\0\0\0\0\0\0\0\0"[..] {
                    IpAddr::from(Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]))
                } else {
                    IpAddr::from(ip_buf)
                };

                Ok(ControlTypes::Handshake(HandshakeControlInfo {
                    udt_version,
                    sock_type,
                    init_seq_num,
                    max_packet_size,
                    max_flow_size,
                    connection_type,
                    socket_id,
                    syn_cookie,
                    peer_addr,
                }))
            }
            0x1 => Ok(ControlTypes::KeepAlive),
            0x2 => {
                // ACK

                // read control info
                let ack_number = SeqNumber::new(buf.get_i32_be());

                // if there is more data, use it. However, it's optional
                let mut opt_read_next = move || {
                    if buf.remaining() > 4 {
                        Some(buf.get_i32_be())
                    } else {
                        None
                    }
                };
                let rtt = opt_read_next();
                let rtt_variance = opt_read_next();
                let buffer_available = opt_read_next();
                let packet_recv_rate = opt_read_next();
                let est_link_cap = opt_read_next();

                Ok(ControlTypes::Ack(
                    extra_info,
                    AckControlInfo {
                        ack_number,
                        rtt,
                        rtt_variance,
                        buffer_available,
                        packet_recv_rate,
                        est_link_cap,
                    },
                ))
            }
            0x3 => {
                // NAK

                let mut loss_info = Vec::new();
                while buf.remaining() >= 4 {
                    loss_info.push(buf.get_i32_be());
                }

                Ok(ControlTypes::Nak(NakControlInfo { loss_info }))
            }
            0x5 => Ok(ControlTypes::Shutdown),
            0x6 => {
                // ACK2
                Ok(ControlTypes::Ack2(extra_info))
            }
            0x7 => {
                // Drop request
                unimplemented!()
            }
            0xFF => {
                // Custom
                Ok(ControlTypes::Custom(reserved, buf.collect()))
            }
            x => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unrecognized control packet type: {:?}", x),
            )),
        }
    }

    fn id_byte(&self) -> u16 {
        match *self {
            ControlTypes::Handshake(_) => 0x0,
            ControlTypes::KeepAlive => 0x1,
            ControlTypes::Ack(_, _) => 0x2,
            ControlTypes::Nak(_) => 0x3,
            ControlTypes::Shutdown => 0x5,
            ControlTypes::Ack2(_) => 0x6,
            ControlTypes::DropRequest(_, _) => 0x7,
            ControlTypes::Custom(_, _) => 0x7FFF,
        }
    }

    fn additional_info(&self) -> i32 {
        match *self {
            // These types have additional info
            ControlTypes::Ack2(i) | ControlTypes::DropRequest(i, _) | ControlTypes::Ack(i, _) => i,
            // These do not, just use zero
            _ => 0,
        }
    }

    fn reserved(&self) -> u16 {
        match *self {
            ControlTypes::Custom(a, _) => a,
            _ => 0,
        }
    }

    fn serialize<T: BufMut>(&self, into: &mut T) {
        match *self {
            ControlTypes::Handshake(ref c) => {
                into.put_i32_be(c.udt_version);
                into.put_i32_be(c.sock_type.to_i32());
                into.put_i32_be(c.init_seq_num.to_i32());
                into.put_i32_be(c.max_packet_size);
                into.put_i32_be(c.max_flow_size);
                into.put_i32_be(c.connection_type.to_i32());
                into.put_i32_be(c.socket_id.0);
                into.put_i32_be(c.syn_cookie);

                match c.peer_addr {
                    IpAddr::V4(four) => {
                        into.put(&four.octets()[..]);

                        // the data structure reuiqres enough space for an ipv6, so pad the end with 16 - 4 = 12 bytes
                        into.put(&b"\0\0\0\0\0\0\0\0\0\0\0\0"[..]);
                    }
                    IpAddr::V6(six) => into.put(&six.octets()[..]),
                }
            }
            ControlTypes::Ack(_, ref c) => {
                into.put_i32_be(c.ack_number.to_i32());
                into.put_i32_be(c.rtt.unwrap_or(10_000));
                into.put_i32_be(c.rtt_variance.unwrap_or(50_000));
                into.put_i32_be(c.buffer_available.unwrap_or(8175)); // TODO: better defaults
                into.put_i32_be(c.packet_recv_rate.unwrap_or(10_000));
                into.put_i32_be(c.est_link_cap.unwrap_or(1_000));
            }
            ControlTypes::Nak(ref n) => for &loss in &n.loss_info {
                into.put_i32_be(loss);
            },
            ControlTypes::DropRequest(_, ref _d) => unimplemented!(),
            // control data
            ControlTypes::Shutdown | ControlTypes::Ack2(_) | ControlTypes::KeepAlive => {}
            ControlTypes::Custom(_, ref data) => into.put(&data[..]),
        };
    }
}

/// The `DropRequest` control info
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DropRequestControlInfo {
    /// The first sequence number in the message to drop
    pub first: SeqNumber,

    /// The last sequence number in the message to drop
    pub last: SeqNumber,
}

/// The NAK control info
#[derive(Debug, Clone, PartialEq)]
pub struct NakControlInfo {
    /// The loss infomration
    /// If a number in this is a seq number (first bit 0),
    /// then the packet with this sequence is lost
    ///
    /// If a packet that's not a seq number (first bit 1),
    /// then all packets starting from this number (including)
    /// to the number in the next integer (including), which must have a zero first bit.
    pub loss_info: Vec<i32>,
}

/// The ACK control info struct
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AckControlInfo {
    /// The packet sequence number that all packets have been recieved until (excluding)
    pub ack_number: SeqNumber,

    /// Round trip time
    pub rtt: Option<i32>,

    /// RTT variance
    pub rtt_variance: Option<i32>,

    /// available buffer
    pub buffer_available: Option<i32>,

    /// receive rate, in packets/sec
    pub packet_recv_rate: Option<i32>,

    /// Estimated Link capacity
    pub est_link_cap: Option<i32>,
}

/// The control info for handshake packets
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandshakeControlInfo {
    /// The UDT version, currently 4
    pub udt_version: i32,

    /// The socket type
    pub sock_type: SocketType,

    /// The initial sequence number, usually randomly initialized
    pub init_seq_num: SeqNumber,

    /// Max packet size, including UDP/IP headers. 1500 by default
    pub max_packet_size: i32,

    /// Max flow window size, by default 25600
    pub max_flow_size: i32,

    /// Connection type, either rendezvois (0) or regular (1)
    pub connection_type: ConnectionType,

    /// The socket ID that this request is originating from
    pub socket_id: SocketID,

    /// SYN cookie
    ///
    /// "generates a cookie value according to the client address and a
    /// secret key and sends it back to the client. The client must then send
    /// back the same cookie to the server."
    pub syn_cookie: i32,

    /// The IP address of the connecting client
    pub peer_addr: IpAddr,
}

/// The socket type for a handshake.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketType {
    /// A stream socket, 1 when serialized
    Stream,

    /// A datagram socket, 2 when serialied
    Datagram,
}

impl SocketType {
    pub fn from_i32(num: i32) -> Result<SocketType> {
        match num {
            1 => Ok(SocketType::Stream),
            2 => Ok(SocketType::Datagram),
            i => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unrecognized socket type: {:?}", i),
            )),
        }
    }

    pub fn to_i32(&self) -> i32 {
        match *self {
            SocketType::Stream => 1,
            SocketType::Datagram => 2,
        }
    }
}

/// See <https://tools.ietf.org/html/draft-gg-udt-03#page-10>
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionType {
    /// A regular connection; one listener and one sender, 1
    Regular,

    /// A rendezvous connection, initial connect request, 0
    RendezvousFirst,

    /// A rendezvous connection, response to initial connect request, -1
    /// Also a regular connection client response to the second handshake
    RendezvousRegularSecond,

    /// Final rendezvous check, -2
    RendezvousFinal,
}

impl ConnectionType {
    pub fn from_i32(num: i32) -> Result<ConnectionType> {
        match num {
            1 => Ok(ConnectionType::Regular),
            0 => Ok(ConnectionType::RendezvousFirst),
            -1 => Ok(ConnectionType::RendezvousRegularSecond),
            -2 => Ok(ConnectionType::RendezvousFinal),
            i => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unrecognized connection type: {:?}", i),
            )),
        }
    }

    pub fn to_i32(&self) -> i32 {
        match *self {
            ConnectionType::Regular => 1,
            ConnectionType::RendezvousFirst => 0,
            ConnectionType::RendezvousRegularSecond => -1,
            ConnectionType::RendezvousFinal => -2,
        }
    }
}

impl Packet {
    pub fn parse<T: Buf>(mut buf: T) -> Result<Packet> {
        // Buffer must be at least 16 bytes,
        // the length of a header packet
        if buf.remaining() < 16 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Packet not long enough to have a header",
            ));
        }

        // get the first four bytes
        let first4: Vec<_> = (0..4).map(|_| buf.get_u8()).collect();

        // Check if the first bit is one or zero;
        // if it's one it's a cotnrol packet,
        // if zero it's a data packet
        if (first4[0] & 0b1 << 7) == 0 {
            // this means it's a data packet

            // get the sequence number, which is the last 31 bits of the header
            // because the first bit is zero, we can just convert the first 4 bits into a
            // 32 bit integer

            let seq_number = SeqNumber::new(Cursor::new(first4).get_i32_be());

            // get the first byte in the second row
            let second_line = buf.get_i32_be();

            let message_loc = PacketLocation::from_i32(second_line);

            // Third bit of FF is delivery order
            let in_order_delivery = (second_line & 0b1 << 29) != 0;

            // clear the first three bits
            let message_number = second_line & !(0b111 << 29);
            let timestamp = buf.get_i32_be();
            let dest_sockid = SocketID(buf.get_i32_be());

            Ok(Packet::Data {
                seq_number,
                message_loc,
                in_order_delivery,
                message_number,
                timestamp,
                dest_sockid,
                payload: buf.collect(),
            })
        } else {
            // this means it's a control packet

            // get reserved data, which is the last two bytes of the first four bytes
            let reserved = Cursor::new(&first4[2..]).get_u16_be();

            let add_info = buf.get_i32_be();
            let timestamp = buf.get_i32_be();
            let dest_sockid = buf.get_i32_be();

            Ok(Packet::Control {
                timestamp,
                dest_sockid: SocketID(dest_sockid),
                // just match against the second byte, as everything is in that
                control_type: ControlTypes::deserialize(
                    ((first4[0] << 1 >> 1) as u16) << 8 + first4[1] as u16,
                    reserved,
                    add_info,
                    buf,
                )?,
            })
        }
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        match *self {
            Packet::Control {
                ref timestamp,
                ref dest_sockid,
                ref control_type,
            } => {
                // first half of first row, the control type and the 1st bit which is a one
                into.put_u16_be(control_type.id_byte() | (0b1 << 15));

                // finish that row, which is reserved
                into.put_u16_be(control_type.reserved());

                // the additonal info line
                into.put_i32_be(control_type.additional_info());

                // timestamp
                into.put_i32_be(*timestamp);

                // dest sock id
                into.put_i32_be(dest_sockid.0);

                // the rest of the info
                control_type.serialize(into);
            }
            Packet::Data {
                ref timestamp,
                ref seq_number,
                ref message_number,
                ref message_loc,
                ref dest_sockid,
                ref payload,
                ref in_order_delivery,
            } => {
                into.put_i32_be(seq_number.to_i32());
                into.put_i32_be(
                    message_number | message_loc.to_i32() |
                        // the third bit in the second row is if it expects in order delivery
                        if *in_order_delivery { 1 << 29 } else { 0 },
                );
                into.put_i32_be(*timestamp);
                into.put_i32_be(dest_sockid.0);
                into.put(payload);
            }
        }
    }
}

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
fn packet_location_to_i32_test() {
    assert_eq!(PacketLocation::First.to_i32(), 0b10 << 30);
    assert_eq!(PacketLocation::Middle.to_i32(), 0b0);
    assert_eq!(PacketLocation::Last.to_i32(), 0b01 << 30);
    assert_eq!(PacketLocation::Only.to_i32(), 0b11 << 30);
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
