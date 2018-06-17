use {SocketID};

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
pub struct ControlPacket {
	/// The timestamp, relative to the socket start time
	timestamp: i32,

	/// The dest socket ID, used for multiplexing
	dest_sockid: SocketID,

	/// The extra data
	control_type: ControlTypes,
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
    Ack{
		/// The ack sequence number of this ack, increments for each ack sent.
		ack_seq_num: i32,
		
		 /// The packet sequence number that all packets have been recieved until (excluding)
    ack_number: SeqNumber,

    /// Round trip time
    rtt: Option<i32>,

    /// RTT variance
    rtt_variance: Option<i32>,

    /// available buffer
    buffer_available: Option<i32>,

    /// receive rate, in packets/sec
    packet_recv_rate: Option<i32>,

    /// Estimated Link capacity
    est_link_cap: Option<i32>,
},

    /// NAK packet, type 0x3
    /// Additional Info isn't used
	/// The information is stored in the loss compression format, specified in the loss_compression module.
    Nak(Vec<u32>),

    /// Shutdown packet, type 0x5
    Shutdown,

    /// Acknowledgement of Acknowledgement (ACK2) 0x6
    /// Additional Info (the i32) is the ACK sequence number to acknowldege
    Ack2(i32),

    /// Drop request, type 0x7
    DropRequest {
		/// The message to drop
		/// Stored in the "addditional info" field of the packet.
		msg_to_drop: i32, 
		
		/// The first sequence number in the message to drop
    	pub first: SeqNumber,

    	/// The last sequence number in the message to drop
    	pub last: SeqNumber,
	},

    /// Custom packets
    /// Mainly used for special SRT handshake packets
    Custom {
		/// The custom data type, stored in bytes 3-4, the "reserved field"
		custom_type: u16, 

		/// The data to store after the packet header
		control_info: Bytes
	},
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
    pub max_packet_size: u32,

    /// Max flow window size, by default 25600
    pub max_flow_size: u32,

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
    /// A stream socket, 0 when serialized
    Stream = 0,

    /// A datagram socket, 2 when serialied
    Datagram = 1,
}

impl SocketType {
    /// Turns a u32 into a SocketType. If the u32 wasn't valid (only 0 and 1 are valid), than it returns Err(num)
    pub fn from_u32(num: u32) -> Result<SocketType, u32> {
        match num {
            0 => Ok(SocketType::Stream),
            1 => Ok(SocketType::Datagram),
            i => Err(i),
        }
    }
}

/// See <https://tools.ietf.org/html/draft-gg-udt-03#page-10>
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionType {
    /// A regular connection; one listener and one sender, 1
    Regular = 1,

    /// A rendezvous connection, initial connect request, 0
    RendezvousFirst = 0,

    /// A rendezvous connection, response to initial connect request, -1
    /// Also a regular connection client response to the second handshake
    RendezvousRegularSecond = -1,

    /// Final rendezvous check, -2
    RendezvousFinal = -2,
}

impl ControlPacket {
	pub fn parse<T: Buf>(mut buf: T) -> Result<ControlPacket, Error> {
            // get reserved data, which is the last two bytes of the first four bytes
            let reserved = Cursor::new(&first4[2..]).get_u16_be();

            let add_info = buf.get_i32_be();
            let timestamp = buf.get_i32_be();
            let dest_sockid = buf.get_u32_be();

            Ok(ControlPacket {
                timestamp,
                dest_sockid: SocketID(dest_sockid),
                // just match against the second byte, as everything is in that
                control_type: ControlTypes::deserialize(
                    ((first4[0] << 1 >> 1) as u16) << 8 | first4[1] as u16,
                    reserved,
                    add_info,
                    buf,
                )?,
            })

	}

	pub fn serialize<T: BufMut>(&self, into: &mut T) {
		// first half of first row, the control type and the 1st bit which is a one
		into.put_u16_be(self.control_type.id_byte() | (0b1 << 15));

		// finish that row, which is reserved
		into.put_u16_be(self.control_type.reserved());

		// the additonal info line
		into.put_i32_be(self.control_type.additional_info());

		// timestamp
		into.put_i32_be(self.timestamp);

		// dest sock id
		into.put_u32_be(self.dest_sockid.0);

		// the rest of the info
		self.control_type.serialize(into);

	}
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
    ) -> Result<ControlTypes, Error> {
        match packet_type {
            0x0 => {
                // Handshake

                let udt_version = buf.get_i32_be();
                let sock_type = match SocketType::from_u32(buf.get_u32_be()) {
                    Ok(st) => st,
                    Err(err_ty) => bail!("Invalid socket type {}", err_ty),
                };
                let init_seq_num = SeqNumber::new(buf.get_u32_be());
                let max_packet_size = buf.get_u32_be();
                let max_flow_size = buf.get_u32_be();
                let connection_type = match ConnectionType::from_i32(buf.get_i32_be()) {
                    Ok(ct) => ct,
                    Err(err_ct) => bail!("Invalid connection type {}", err_ct),
                };
                let socket_id = SocketID(buf.get_u32_be());
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
                let ack_number = SeqNumber::new(buf.get_u32_be());

                // if there is more data, use it. However, it's optional
                let mut opt_read_next = move || {
                    if buf.remaining() >= 4 {
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
                    loss_info.push(buf.get_u32_be());
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
            x => Err(format_err!("Unrecognized control packet type: {:?}", x)),
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
                into.put_u32_be(c.sock_type as u32);
                into.put_u32_be(c.init_seq_num.as_raw());
                into.put_u32_be(c.max_packet_size);
                into.put_u32_be(c.max_flow_size);
                into.put_i32_be(c.connection_type as i32);
                into.put_u32_be(c.socket_id.0);
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
                into.put_u32_be(c.ack_number.as_raw());
                into.put_i32_be(c.rtt.unwrap_or(10_000));
                into.put_i32_be(c.rtt_variance.unwrap_or(50_000));
                into.put_i32_be(c.buffer_available.unwrap_or(8175)); // TODO: better defaults
                into.put_i32_be(c.packet_recv_rate.unwrap_or(10_000));
                into.put_i32_be(c.est_link_cap.unwrap_or(1_000));
            }
            ControlTypes::Nak(ref n) => for &loss in &n.loss_info {
                into.put_u32_be(loss);
            },
            ControlTypes::DropRequest(_, ref _d) => unimplemented!(),
            // control data
            ControlTypes::Shutdown | ControlTypes::Ack2(_) | ControlTypes::KeepAlive => {}
            ControlTypes::Custom(_, ref data) => into.put(&data[..]),
        };
    }
}

impl ConnectionType {
    /// Turns an i32 into a `ConnectionType`, returning Err(num) if no valid one was passed.
    pub fn from_i32(num: i32) -> Result<ConnectionType, i32> {
        match num {
            1 => Ok(ConnectionType::Regular),
            0 => Ok(ConnectionType::RendezvousFirst),
            -1 => Ok(ConnectionType::RendezvousRegularSecond),
            -2 => Ok(ConnectionType::RendezvousFinal),
            i => Err(i),
        }
    }
}



