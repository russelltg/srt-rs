use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use failure::{bail, format_err, Error};
use log::warn;

use crate::{SeqNumber, SocketID};

mod srt;

pub use self::srt::{SrtControlPacket, SrtHandshake, SrtShakeFlags};

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
#[derive(Debug, Clone, PartialEq)]
pub struct ControlPacket {
    /// The timestamp, relative to the socket start time
    pub timestamp: i32,

    /// The dest socket ID, used for multiplexing
    pub dest_sockid: SocketID,

    /// The extra data
    pub control_type: ControlTypes,
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
    Ack {
        /// The ack sequence number of this ack, increments for each ack sent.
        /// Stored in additional info
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
        first: SeqNumber,

        /// The last sequence number in the message to drop
        last: SeqNumber,
    },

    /// Srt control packets
    /// These use the UDT extension type 0xFF
    Srt(SrtControlPacket),
}

bitflags! {
    /// Used to describe the extension types in the packet
    struct ExtFlags: u32 {
        /// The packet has a handshake extension
        const HS = 0b1;
        /// The packet has a kmreq extension
        const KM = 0b10;
        /// The packet has a config extension (SID or smoother)
        const CONFIG = 0b100;
    }
}

/// HS-version dependenent data
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeVSInfo {
    V4(SocketType),
    V5 {
        /// The extension HSReq/HSResp
        ext_hs: Option<SrtControlPacket>,

        /// The extension KMREQ/KMRESP
        ext_km: Option<SrtControlPacket>,

        /// The extension config (SID, smoother)
        ext_config: Option<SrtControlPacket>,
    },
}

/// The control info for handshake packets
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandshakeControlInfo {
    /// The initial sequence number, usually randomly initialized
    pub init_seq_num: SeqNumber,

    /// Max packet size, including UDP/IP headers. 1500 by default
    pub max_packet_size: u32,

    /// Max flow window size, by default 25600
    pub max_flow_size: u32,

    /// Connection type, either rendezvois (0) or regular (1)
    pub shake_type: ShakeType,

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

    /// The rest of the data, which is HS version specific
    pub info: HandshakeVSInfo,
}

/// The socket type for a handshake.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketType {
    /// A stream socket, 1 when serialized
    Stream = 1,

    /// A datagram socket, 2 when serialied
    Datagram = 2,
}

/// See <https://tools.ietf.org/html/draft-gg-udt-03#page-10>
///
/// More applicably,
///
/// Note: the client-server connection uses:
/// --> INDUCTION (empty)
/// <-- INDUCTION (cookie)
/// --> CONCLUSION (cookie)
/// <-- CONCLUSION (ok)
///
/// The rendezvous HSv4 (legacy):
/// --> WAVEAHAND (effective only if peer is also connecting)
/// <-- CONCLUSION (empty) (consider yourself connected upon reception)
/// --> AGREEMENT (sent as a response for conclusion, requires no response)
///
/// The rendezvous HSv5 (using SRT extensions):
/// --> WAVEAHAND (with cookie)
/// --- (selecting INITIATOR/RESPONDER by cookie contest - comparing one another's cookie)
/// <-- CONCLUSION (without extensions, if RESPONDER, with extensions, if INITIATOR)
/// --> CONCLUSION (with response extensions, if RESPONDER)
/// <-- AGREEMENT (sent exclusively by INITIATOR upon reception of CONCLUSIOn with response extensions)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShakeType {
    /// First handshake exchange in client-server connection
    Induction = 1,

    /// A rendezvous connection, initial connect request, 0
    Waveahand = 0,

    /// A rendezvous connection, response to initial connect request, -1
    /// Also a regular connection client response to the second handshake
    Conclusion = -1,

    /// Final rendezvous check, -2
    Agreement = -2,
}

impl HandshakeVSInfo {
    /// Get the type (V4) or ext flags (V5)
    fn type_flags(&self) -> u32 {
        match self {
            HandshakeVSInfo::V4(ty) => *ty as u32,
            HandshakeVSInfo::V5 {
                ext_hs,
                ext_km,
                ext_config,
            } => {
                let mut flags = ExtFlags::empty();

                if ext_hs.is_some() {
                    flags |= ExtFlags::HS;
                }
                if ext_km.is_some() {
                    flags |= ExtFlags::KM;
                }
                if ext_config.is_some() {
                    flags |= ExtFlags::CONFIG;
                }
                flags.bits()
            }
        }
    }

    /// Get the UDT version
    fn version(&self) -> u32 {
        match self {
            HandshakeVSInfo::V4(_) => 4,
            HandshakeVSInfo::V5 { .. } => 5,
        }
    }
}

impl SocketType {
    /// Turns a u32 into a SocketType. If the u32 wasn't valid (only 1 and 2 are valid), than it returns Err(num)
    pub fn from_u32(num: u32) -> Result<SocketType, u32> {
        match num {
            1 => Ok(SocketType::Stream),
            2 => Ok(SocketType::Datagram),
            i => Err(i),
        }
    }
}

impl ControlPacket {
    pub fn parse<T: Buf>(mut buf: T) -> Result<ControlPacket, Error> {
        // get reserved data, which is the last two bytes of the first four bytes
        let control_type = buf.get_u16_be() << 1 >> 1; // clear first bit
        let reserved = buf.get_u16_be();
        let add_info = buf.get_i32_be();
        let timestamp = buf.get_i32_be();
        let dest_sockid = buf.get_u32_be();

        Ok(ControlPacket {
            timestamp,
            dest_sockid: SocketID(dest_sockid),
            // just match against the second byte, as everything is in that
            control_type: ControlTypes::deserialize(control_type, reserved, add_info, buf)?,
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

// I definitely don't totally understand this yet.
// Points of interest: handshake.h:wrapFlags
// core.cpp:8176 (processConnectionRequest -> if INDUCTION)
const SRT_MAGIC_CODE: u32 = 0x4A17;

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
                if udt_version != 4 && udt_version != 5 {
                    bail!("Incompatable UDT version: {}", udt_version);
                }

                let mut type_ext = buf.get_u32_be();
                let init_seq_num = SeqNumber::new(buf.get_u32_be());
                let max_packet_size = buf.get_u32_be();
                let max_flow_size = buf.get_u32_be();
                let shake_type = match ShakeType::from_i32(buf.get_i32_be()) {
                    Ok(ct) => ct,
                    Err(err_ct) => bail!("Invalid connection type {}", err_ct),
                };
                let socket_id = SocketID(buf.get_u32_be());
                let syn_cookie = buf.get_i32_be();

                // get the IP
                let mut ip_buf: [u8; 16] = [0; 16];
                buf.copy_to_slice(&mut ip_buf);

                // TODO: this is probably really wrong, so fix it
                let peer_addr = if ip_buf[4..] == [0; 12][..] {
                    IpAddr::from(Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]))
                } else {
                    IpAddr::from(ip_buf)
                };

                let info = match udt_version {
                    4 => HandshakeVSInfo::V4(match SocketType::from_u32(type_ext) {
                        Ok(t) => t,
                        Err(e) => {
                            bail!("Unrecognized socket type: {}", e);
                        }
                    }),
                    5 => {
                        // TODO: I still don't understand. This is likely incorrect
                        if type_ext == SRT_MAGIC_CODE {
                            type_ext = 0;
                        }
                        let extensions = match ExtFlags::from_bits(type_ext) {
                            Some(i) => i,
                            None => {
                                warn!("Unnecessary bits in extensions flags: {:b}", type_ext);

                                ExtFlags::from_bits_truncate(type_ext)
                            }
                        };
                        // parse out extensions
                        let ext_hs = if extensions.contains(ExtFlags::HS) {
                            let pack_type = buf.get_u16_be();
                            let _pack_size = buf.get_u16_be(); // TODO: why exactly is this needed?
                            match pack_type {
                                // 1 and 2 are handshake response and requests
                                1 | 2 => Some(SrtControlPacket::parse(pack_type, &mut buf)?),
                                e => bail!(
                                    "Expected 1 or 2 (SRT handshake request or response), got {}",
                                    e
                                ),
                            }
                        } else {
                            None
                        };
                        let ext_km = if extensions.contains(ExtFlags::KM) {
                            let pack_type = buf.get_u16_be();
                            let _pack_size = buf.get_u16_be(); // TODO: why exactly is this needed?
                            match pack_type {
                                // 3 and 4 are km packets
                                3 | 4 => Some(SrtControlPacket::parse(pack_type, &mut buf)?),
                                e => bail!(
                                    "Exepcted 3 or 4 (SRT key manager request or response), got {}",
                                    e
                                ),
                            }
                        } else {
                            None
                        };
                        let ext_config = if extensions.contains(ExtFlags::CONFIG) {
                            let pack_type = buf.get_u16_be();
                            let _pack_size = buf.get_u16_be(); // TODO: why exactly is this needed?
                            match pack_type {
                                // 5 is sid 6 is smoother
                                5 | 6 => Some(SrtControlPacket::parse(pack_type, &mut buf)?),
                                e => bail!("Expected 5 or 6 (SRT SID or smoother), got {}", e),
                            }
                        } else {
                            None
                        };
                        HandshakeVSInfo::V5 {
                            ext_hs,
                            ext_km,
                            ext_config,
                        }
                    }
                    _ => unreachable!(), // this is already checked for above
                };

                Ok(ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num,
                    max_packet_size,
                    max_flow_size,
                    shake_type,
                    socket_id,
                    syn_cookie,
                    peer_addr,
                    info,
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

                Ok(ControlTypes::Ack {
                    ack_seq_num: extra_info,
                    ack_number,
                    rtt,
                    rtt_variance,
                    buffer_available,
                    packet_recv_rate,
                    est_link_cap,
                })
            }
            0x3 => {
                // NAK

                let mut loss_info = Vec::new();
                while buf.remaining() >= 4 {
                    loss_info.push(buf.get_u32_be());
                }

                Ok(ControlTypes::Nak(loss_info))
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
            0x7FFF => {
                // Srt
                Ok(ControlTypes::Srt(SrtControlPacket::parse(
                    reserved, &mut buf,
                )?))
            }
            x => Err(format_err!("Unrecognized control packet type: {:?}", x)),
        }
    }

    fn id_byte(&self) -> u16 {
        match *self {
            ControlTypes::Handshake(_) => 0x0,
            ControlTypes::KeepAlive => 0x1,
            ControlTypes::Ack { .. } => 0x2,
            ControlTypes::Nak(_) => 0x3,
            ControlTypes::Shutdown => 0x5,
            ControlTypes::Ack2(_) => 0x6,
            ControlTypes::DropRequest { .. } => 0x7,
            ControlTypes::Srt(_) => 0x7FFF,
        }
    }

    fn additional_info(&self) -> i32 {
        match *self {
            // These types have additional info
            ControlTypes::Ack2(a)
            | ControlTypes::DropRequest { msg_to_drop: a, .. }
            | ControlTypes::Ack { ack_seq_num: a, .. } => a,
            // These do not, just use zero
            _ => 0,
        }
    }

    fn reserved(&self) -> u16 {
        match *self {
            ControlTypes::Srt(srt) => srt.type_id(),
            _ => 0,
        }
    }

    fn serialize<T: BufMut>(&self, into: &mut T) {
        match *self {
            ControlTypes::Handshake(ref c) => {
                into.put_u32_be(c.info.version());
                into.put_u32_be(c.info.type_flags());
                into.put_u32_be(c.init_seq_num.as_raw());
                into.put_u32_be(c.max_packet_size);
                into.put_u32_be(c.max_flow_size);
                into.put_i32_be(c.shake_type as i32);
                into.put_u32_be(c.socket_id.0);
                into.put_i32_be(c.syn_cookie);

                match c.peer_addr {
                    IpAddr::V4(four) => {
                        into.put(&four.octets()[..]);

                        // the data structure reuiqres enough space for an ipv6, so pad the end with 16 - 4 = 12 bytes
                        into.put(&[0; 12][..]);
                    }
                    IpAddr::V6(six) => into.put(&six.octets()[..]),
                }

                // serialzie extensions
                if let HandshakeVSInfo::V5 {
                    ext_hs,
                    ext_km,
                    ext_config,
                } = c.info
                {
                    for ext in [ext_hs, ext_km, ext_config].iter().filter_map(|&s| s) {
                        into.put_u16_be(ext.type_id());
                        // put the size in 32-bit integers
                        into.put_u16_be(3); // TODO: please no pleeeasseee nooo
                        ext.serialize(into);
                    }
                }
            }
            ControlTypes::Ack {
                ack_number,
                rtt,
                rtt_variance,
                buffer_available,
                packet_recv_rate,
                est_link_cap,
                ..
            } => {
                into.put_u32_be(ack_number.as_raw());
                into.put_i32_be(rtt.unwrap_or(10_000));
                into.put_i32_be(rtt_variance.unwrap_or(50_000));
                into.put_i32_be(buffer_available.unwrap_or(8175)); // TODO: better defaults
                into.put_i32_be(packet_recv_rate.unwrap_or(10_000));
                into.put_i32_be(est_link_cap.unwrap_or(1_000));
            }
            ControlTypes::Nak(ref n) => {
                for &loss in n {
                    into.put_u32_be(loss);
                }
            }
            ControlTypes::DropRequest { .. } => unimplemented!(),
            // control data
            ControlTypes::Shutdown | ControlTypes::Ack2(_) | ControlTypes::KeepAlive => {}
            ControlTypes::Srt(srt) => {
                srt.serialize(into);
            }
        };
    }
}

impl ShakeType {
    /// Turns an i32 into a `ConnectionType`, returning Err(num) if no valid one was passed.
    pub fn from_i32(num: i32) -> Result<ShakeType, i32> {
        match num {
            1 => Ok(ShakeType::Induction),
            0 => Ok(ShakeType::Waveahand),
            -1 => Ok(ShakeType::Conclusion),
            -2 => Ok(ShakeType::Agreement),
            i => Err(i),
        }
    }
}

#[cfg(test)]
mod test {

    use super::{
        ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType,
        SrtControlPacket, SrtHandshake, SrtShakeFlags,
    };
    use crate::{SeqNumber, SocketID, SrtVersion};
    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn handshake_ser_des_test() {
        let pack = ControlPacket {
            timestamp: 0,
            dest_sockid: SocketID(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber::new(1827131),
                max_packet_size: 1500,
                max_flow_size: 25600,
                shake_type: ShakeType::Induction,
                socket_id: SocketID(1231),
                syn_cookie: 0,
                peer_addr: "127.0.0.1".parse().unwrap(),
                info: HandshakeVSInfo::V5 {
                    ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                        version: SrtVersion::CURRENT,
                        flags: SrtShakeFlags::NAKREPORT | SrtShakeFlags::TSBPDSND,
                        latency: Duration::from_millis(12345),
                    })),
                    ext_km: None,
                    ext_config: None,
                },
            }),
        };

        let mut buf = vec![];
        pack.serialize(&mut buf);

        let des = ControlPacket::parse(Cursor::new(buf)).unwrap();

        assert_eq!(pack, des);
    }

    #[test]
    fn ack_ser_des_test() {
        let pack = ControlPacket {
            timestamp: 113703,
            dest_sockid: SocketID(2453706529),
            control_type: ControlTypes::Ack {
                ack_seq_num: 1,
                ack_number: SeqNumber::new(282049186),
                rtt: Some(10002),
                rtt_variance: Some(1000),
                buffer_available: Some(1314),
                packet_recv_rate: Some(0),
                est_link_cap: Some(0),
            },
        };

        let mut buf = vec![];
        pack.serialize(&mut buf);

        let des = ControlPacket::parse(Cursor::new(buf)).unwrap();

        assert_eq!(pack, des);
    }

    #[test]
    fn ack2_ser_des_test() {
        let pack = ControlPacket {
            timestamp: 125812,
            dest_sockid: SocketID(8313),
            control_type: ControlTypes::Ack2(831),
        };
        assert_eq!(pack.control_type.additional_info(), 831);

        let mut buf = vec![];
        pack.serialize(&mut buf);

        // dword 2 should have 831 in big endian, so the last two bits of the second dword
        assert_eq!(((buf[6] as u32) << 8) + buf[7] as u32, 831);

        let des = ControlPacket::parse(Cursor::new(buf)).unwrap();

        assert_eq!(pack, des);
    }
}
