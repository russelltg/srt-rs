mod loss_compression;
mod srt;

pub use srt::*;

use std::{
    array::IntoIter,
    convert::TryFrom,
    convert::TryInto,
    fmt::{self, Debug, Display, Formatter},
    iter::FromIterator,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Add, Range, RangeInclusive, Sub},
};

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use log::warn;

use super::*;

use loss_compression::{compress_loss_list, decompress_loss_list};

/// A UDP packet carrying control information
///
/// ```ignore,
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
/// ```
/// (from <https://tools.ietf.org/html/draft-gg-udt-03#page-5>)
#[derive(Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// The timestamp, relative to the socket start time (wrapping every 2^32 microseconds)
    pub timestamp: TimeStamp,

    /// The dest socket ID, used for multiplexing
    pub dest_sockid: SocketId,

    /// The extra data
    pub control_type: ControlTypes,
}

/// The different kind of control packets
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ControlTypes {
    /// The control packet for initiating connections, type 0x0
    /// Does not use Additional Info
    Handshake(HandshakeControlInfo),

    /// To keep a connection alive
    /// Does not use Additional Info or Control Info, type 0x1
    KeepAlive,

    /// ACK packet, type 0x2
    Ack(Acknowledgement),

    /// NAK packet, type 0x3
    /// Additional Info isn't used
    Nak(CompressedLossList),

    // Congestion warning packet, type 0x4
    CongestionWarning,

    /// Shutdown packet, type 0x5
    Shutdown,

    /// Acknowledgement of Acknowledgement (ACK2) 0x6
    /// Additional Info (the i32) is the ACK sequence number to acknowldege
    Ack2(FullAckSeqNumber),

    /// Drop request, type 0x7
    DropRequest {
        /// The message to drop
        /// Stored in the "addditional info" field of the packet.
        msg_to_drop: MsgNumber,

        /// The range of sequence numbers in the message to drop
        range: RangeInclusive<SeqNumber>,
    },

    // Peer error, type 0x8
    PeerError(u32),

    /// Srt control packets
    /// These use the UDT extension type 0xFF
    Srt(SrtControlPacket),
}

bitflags! {
    /// Used to describe the extension types in the packet
    struct ExtFlags: u16 {
        /// The packet has a handshake extension
        const HS = 0b1;
        /// The packet has a kmreq extension
        const KM = 0b10;
        /// The packet has a config extension (SID or smoother or filter or group)
        const CONFIG = 0b100;
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HsV5Info {
    /// the crypto size in bytes, either 0 (no encryption), 16, 24, or 32 (stored /8)
    /// source: https://github.com/Haivision/srt/blob/master/docs/stransmit.md#medium-srt
    pub crypto_size: u8,

    /// The extension HSReq/HSResp
    pub ext_hs: Option<SrtControlPacket>,

    /// The extension KMREQ/KMRESP
    pub ext_km: Option<SrtControlPacket>,

    pub ext_group: Option<SrtControlPacket>,

    /// The SID
    pub sid: Option<String>,
}

/// HS-version dependenent data
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum HandshakeVsInfo {
    V4(SocketType),
    V5(HsV5Info),
}

/// The control info for handshake packets
#[derive(Clone, PartialEq, Eq)]
pub struct HandshakeControlInfo {
    /// The initial sequence number, usually randomly initialized
    pub init_seq_num: SeqNumber,

    /// Max packet size, including UDP/IP headers. 1500 by default
    pub max_packet_size: u32,

    /// Max flow window size, by default 25600
    pub max_flow_size: u32,

    /// Designates where in the handshake process this packet lies
    pub shake_type: ShakeType,

    /// The socket ID that this request is originating from
    pub socket_id: SocketId,

    /// SYN cookie
    ///
    /// "generates a cookie value according to the client address and a
    /// secret key and sends it back to the client. The client must then send
    /// back the same cookie to the server."
    pub syn_cookie: i32,

    /// The IP address of the connecting client
    pub peer_addr: IpAddr,

    /// The rest of the data, which is HS version specific
    pub info: HandshakeVsInfo,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AckStatistics {
    /// Round trip time
    pub rtt: TimeSpan,
    /// RTT variance
    pub rtt_variance: TimeSpan,
    /// available buffer, in packets
    pub buffer_available: u32,
    /// receive rate, in packets/sec
    pub packet_receive_rate: Option<u32>,
    /// Estimated Link capacity in packets/sec
    pub estimated_link_capacity: Option<u32>,
    /// Receive rate, in bytes/sec
    pub data_receive_rate: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Debug, Copy, Ord, PartialOrd)]
pub struct FullAckSeqNumber(u32);

/// Data included in a ACK packet. [spec](https://datatracker.ietf.org/doc/html/draft-sharabayko-mops-srt-00#section-3.2.3)
///
/// There are three types of ACK packets:
/// * Full - includes all the fields
/// * Lite - no optional fields
/// * Small - Includes rtt, rtt_variance, and buffer_available
///
/// However, these aren't necessarily clean categories--there may be some
/// amount of overlap so full acks are allowed to have no extra info and short acks
/// are allowed to have all the info
///
/// SeqNumber is the packet sequence number that all packets have been received until (excluding)
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Acknowledgement {
    Lite(SeqNumber),
    Small(SeqNumber, AckStatistics),
    Full(SeqNumber, AckStatistics, FullAckSeqNumber),
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompressedLossList(Vec<u32>);

/// The socket type for a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShakeType {
    /// First handshake exchange in client-server connection
    Induction,

    /// A rendezvous connection, initial connect request, 0
    Waveahand,

    /// A rendezvous connection, response to initial connect request, -1
    /// Also a regular connection client response to the second handshake
    Conclusion,

    /// Final rendezvous check, -2
    Agreement,

    /// Reject
    Rejection(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreRejectReason {
    System = 1001,
    Peer = 1002,
    Resource = 1003,
    Rogue = 1004,
    Backlog = 1005,
    Ipe = 1006,
    Close = 1007,
    Version = 1008,
    RdvCookie = 1009,
    BadSecret = 1010,
    Unsecure = 1011,
    MessageApi = 1012,
    Congestion = 1013,
    Filter = 1014,
    Group = 1015,
    Timeout = 1016,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRejectReason {
    Fallback = 2000,
    KeyNotSup = 2001,
    Filepath = 2002,
    HostNotFound = 2003,
    BadRequest = 2400,
    Unauthorized = 2401,
    Overload = 2402,
    Forbidden = 2403,
    Notfound = 2404,
    BadMode = 2405,
    Unacceptable = 2406,
    Conflict = 2409,
    NotSupMedia = 2415,
    Locked = 2423,
    FailedDepend = 2424,
    InternalServerError = 2500,
    Unimplemented = 2501,
    Gateway = 2502,
    Down = 2503,
    Version = 2505,
    NoRoom = 2507,
}

/// Reject code
/// *must* be >= 1000
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Core reject codes, [1000, 2000)
    Core(CoreRejectReason),
    CoreUnrecognized(i32),

    /// Server reject codes, [2000, 3000)
    Server(ServerRejectReason),
    ServerUnrecognized(i32),

    /// User reject code, >3000
    User(i32),
}

impl HandshakeVsInfo {
    /// Get the type (V4) or ext flags (V5)
    /// the shake_type is required to decide to encode the magic code
    fn type_flags(&self, shake_type: ShakeType) -> u32 {
        match self {
            HandshakeVsInfo::V4(ty) => *ty as u32,
            HandshakeVsInfo::V5(hs) => {
                if shake_type == ShakeType::Induction
                    && (hs.ext_hs.is_some() || hs.ext_km.is_some() || hs.sid.is_some())
                {
                    // induction does not include any extensions, and instead has the
                    // magic code. this is an incompatialbe place to be.
                    panic!("Handshake is both induction and has SRT extensions, not valid");
                }

                let mut flags = ExtFlags::empty();

                if hs.ext_hs.is_some() {
                    flags |= ExtFlags::HS;
                }
                if hs.ext_km.is_some() {
                    flags |= ExtFlags::KM;
                }
                if hs.sid.is_some() {
                    flags |= ExtFlags::CONFIG;
                }
                // take the crypto size, get rid of the frist three (guaranteed zero) bits, then shift it into the
                // most significant 2-byte word
                (u32::from(hs.crypto_size) >> 3 << 16)
                    // when this is an induction packet, includ the magic code instead of flags
                    | if shake_type == ShakeType::Induction {
                    u32::from(SRT_MAGIC_CODE)
                } else {
                    u32::from(flags.bits())
                }
            }
        }
    }

    /// Get the UDT version
    pub fn version(&self) -> u32 {
        match self {
            HandshakeVsInfo::V4(_) => 4,
            HandshakeVsInfo::V5 { .. } => 5,
        }
    }
}

impl SocketType {
    /// Turns a u32 into a SocketType. If the u32 wasn't valid (only 1 and 2 are valid), than it returns Err(num)
    pub fn from_u16(num: u16) -> Result<SocketType, u16> {
        match num {
            1 => Ok(SocketType::Stream),
            2 => Ok(SocketType::Datagram),
            i => Err(i),
        }
    }
}

impl ControlPacket {
    pub fn parse(buf: &mut impl Buf, is_ipv6: bool) -> Result<ControlPacket, PacketParseError> {
        let control_type = buf.get_u16() << 1 >> 1; // clear first bit

        // get reserved data, which is the last two bytes of the first four bytes
        let reserved = buf.get_u16();
        let add_info = buf.get_u32();
        let timestamp = TimeStamp::from_micros(buf.get_u32());
        let dest_sockid = buf.get_u32();

        Ok(ControlPacket {
            timestamp,
            dest_sockid: SocketId(dest_sockid),
            // just match against the second byte, as everything is in that
            control_type: ControlTypes::deserialize(
                control_type,
                reserved,
                add_info,
                buf,
                is_ipv6,
            )?,
        })
    }

    pub fn serialize<T: BufMut>(&self, into: &mut T) {
        // first half of first row, the control type and the 1st bit which is a one
        into.put_u16(self.control_type.id_byte() | (0b1 << 15));

        // finish that row, which is reserved
        into.put_u16(self.control_type.reserved());

        // the additonal info line
        into.put_u32(self.control_type.additional_info());

        // timestamp
        into.put_u32(self.timestamp.as_micros());

        // dest sock id
        into.put_u32(self.dest_sockid.0);

        // the rest of the info
        self.control_type.serialize(into);
    }

    pub fn handshake(&self) -> Option<&HandshakeControlInfo> {
        if let ControlTypes::Handshake(hs) = &self.control_type {
            Some(hs)
        } else {
            None
        }
    }

    pub fn wire_size(&self) -> usize {
        // 20 bytes IPv4 + 8 bytes of UDP + 16 bytes SRT header.
        20 + 8
            + 16
            + match &self.control_type {
                ControlTypes::Handshake(hs) => hs.serialized_size(),
                ControlTypes::Ack(ack) => ack.serialized_size(),
                ControlTypes::Nak(nak) => nak.0.len() * size_of::<u32>(),
                ControlTypes::DropRequest { .. } => 3 * size_of::<u32>(),
                ControlTypes::Srt(srt) => usize::from(srt.size_words()) * size_of::<u32>(),
                ControlTypes::CongestionWarning
                | ControlTypes::Ack2(_)
                | ControlTypes::Shutdown
                | ControlTypes::KeepAlive
                | ControlTypes::PeerError(_) => 4,
            }
    }
}

impl Debug for ControlPacket {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{{{:?} ts={:?} dst={:?}}}",
            self.control_type, self.timestamp, self.dest_sockid,
        )
    }
}

// I definitely don't totally understand this yet.
// Points of interest: handshake.h:wrapFlags
// core.cpp:8176 (processConnectionRequest -> if INDUCTION)
const SRT_MAGIC_CODE: u16 = 0x4A17;

impl ControlTypes {
    pub fn new_drop_request(msg_to_drop: MsgNumber, drop_range: Range<SeqNumber>) -> Self {
        assert!(!drop_range.is_empty());
        Self::DropRequest {
            msg_to_drop,
            range: RangeInclusive::new(drop_range.start, drop_range.end - 1),
        }
    }

    pub fn new_key_refresh_request(key_material: KeyingMaterialMessage) -> ControlTypes {
        ControlTypes::Srt(SrtControlPacket::KeyRefreshRequest(key_material))
    }

    /// Deserialize a control info
    /// * `packet_type` - The packet ID byte, the second byte in the first row
    /// * `reserved` - the second 16 bytes of the first row, reserved for custom packets
    fn deserialize<T: Buf>(
        packet_type: u16,
        reserved: u16,
        extra_info: u32,
        mut buf: T,
        is_ipv6: bool,
    ) -> Result<ControlTypes, PacketParseError> {
        match packet_type {
            0x0 => {
                // Handshake
                // make sure the packet is large enough -- 8 32-bit words, 1 128 (ip)
                if buf.remaining() < 8 * 4 + 16 {
                    return Err(PacketParseError::NotEnoughData);
                }

                let udt_version = buf.get_i32();
                if udt_version != 4 && udt_version != 5 {
                    return Err(PacketParseError::BadUdtVersion(udt_version));
                }

                // the second 32 bit word is always socket type under UDT4
                // under SRT HSv5, it is a bit more complex:
                //
                // byte 1-2: the crypto key size, rightshifted by three. For example 0b11 would translate to a crypto size of 24
                //           source: https://github.com/Haivision/srt/blob/4f7f2beb2e1e306111b9b11402049a90cb6d3787/srtcore/handshake.h#L123-L125
                let crypto_size = buf.get_u16() << 3;
                // byte 3-4: the SRT_MAGIC_CODE, to make sure a client is HSv5 or the ExtFlags if this is an induction response
                //           else, this is the extension flags
                //
                // it's ok to only have the lower 16 bits here for the socket type because socket types always have a zero upper 16 bits
                let type_ext_socket_type = buf.get_u16();

                let init_seq_num = SeqNumber::new_truncate(buf.get_u32()); // TODO: should this truncate?
                let max_packet_size = buf.get_u32();
                let max_flow_size = buf.get_u32();
                let shake_type = match ShakeType::try_from(buf.get_i32()) {
                    Ok(ct) => ct,
                    Err(err_ct) => return Err(PacketParseError::BadConnectionType(err_ct)),
                };
                let socket_id = SocketId(buf.get_u32());
                let syn_cookie = buf.get_i32();

                let peer_addr = if !is_ipv6 {
                    let ip = buf.get_u32_le();
                    buf.get_u32();
                    buf.get_u32();
                    buf.get_u32();
                    IpAddr::from(Ipv4Addr::from(ip))
                } else {
                    let mut ip_buf = [0u8; 16];
                    buf.copy_to_slice(&mut ip_buf);
                    IpAddr::from(Ipv6Addr::from(ip_buf))
                };

                let info = match udt_version {
                    4 => HandshakeVsInfo::V4(match SocketType::from_u16(type_ext_socket_type) {
                        Ok(t) => t,
                        Err(e) => return Err(PacketParseError::BadSocketType(e)),
                    }),
                    5 => {
                        // make sure crypto size is of a valid variant
                        let crypto_size = match crypto_size {
                            0 | 16 | 24 | 32 => crypto_size as u8,
                            c => {
                                warn!(
                                    "Unrecognized crypto key length: {}, disabling encryption. Should be 0, 16, 24, or 32 bytes.",
                                    c
                                );
                                0
                            }
                        };

                        if shake_type == ShakeType::Induction {
                            if type_ext_socket_type != SRT_MAGIC_CODE {
                                // TODO: should this bail? What does the reference implementation do?
                                warn!("HSv5 induction response did not have SRT_MAGIC_CODE, which is suspicious")
                            }

                            HandshakeVsInfo::V5(HsV5Info::default())
                        } else {
                            // if this is not induction, this is the extension flags
                            let extensions = match ExtFlags::from_bits(type_ext_socket_type) {
                                Some(i) => i,
                                None => {
                                    warn!(
                                        "Unnecessary bits in extensions flags: {:b}",
                                        type_ext_socket_type
                                    );

                                    ExtFlags::from_bits_truncate(type_ext_socket_type)
                                }
                            };

                            // parse out extensions

                            let mut sid = None;
                            let mut ext_hs = None;
                            let mut ext_km = None;

                            while buf.remaining() > 4 {
                                let pack_type = buf.get_u16();

                                let pack_size_words = buf.get_u16();
                                let pack_size = usize::from(pack_size_words) * 4;

                                if buf.remaining() < pack_size {
                                    return Err(PacketParseError::NotEnoughData);
                                }

                                let mut buffer = buf.take(pack_size);
                                match pack_type {
                                    1 | 2 => {
                                        if !extensions.contains(ExtFlags::HS) {
                                            warn!("Handshake contains handshake extension type {} without HSREQ flag!", pack_type);
                                        }
                                        if ext_hs != None {
                                            warn!("Handshake contains multiple handshake extensions, only the last will be applied!");
                                        }
                                        ext_hs =
                                            Some(SrtControlPacket::parse(pack_type, &mut buffer)?);
                                    }
                                    3 | 4 => {
                                        if !extensions.contains(ExtFlags::KM) {
                                            warn!("Handshake contains key material extension type {} without KMREQ flag!", pack_type);
                                        }
                                        if ext_km != None {
                                            warn!("Handshake contains multiple key material extensions, only the last will be applied!");
                                        }
                                        ext_km =
                                            Some(SrtControlPacket::parse(pack_type, &mut buffer)?);
                                    }
                                    _ => {
                                        if !extensions.contains(ExtFlags::CONFIG) {
                                            warn!("Handshake contains config extension type {} without CONFIG flag!", pack_type);
                                        }
                                        match SrtControlPacket::parse(pack_type, &mut buffer)? {
                                            //5 = sid:
                                            SrtControlPacket::StreamId(stream_id) => {
                                                sid = Some(stream_id)
                                            }
                                            _ => unimplemented!("Implement other kinds"),
                                        }
                                    }
                                }
                                buf = buffer.into_inner();
                            }

                            if buf.remaining() != 0 {
                                warn!("Handshake has data left, but not enough for an extension!");
                            }
                            if ext_hs.is_none() && extensions.contains(ExtFlags::HS) {
                                warn!("Handshake has HSREQ flag, but contains no handshake extensions!");
                            }
                            if ext_km.is_none() && extensions.contains(ExtFlags::KM) {
                                warn!("Handshake has KMREQ flag, but contains no key material extensions!");
                            }

                            HandshakeVsInfo::V5(HsV5Info {
                                crypto_size,
                                ext_hs,
                                ext_km,
                                ext_group: None,
                                sid,
                            })
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
            0x1 => {
                // discard the "unused" packet field, if it exists
                if buf.remaining() >= 4 {
                    buf.get_u32();
                }
                Ok(ControlTypes::KeepAlive)
            }
            0x2 => {
                // ACK

                // make sure there are enough bytes -- only one required field
                if buf.remaining() < 4 {
                    return Err(PacketParseError::NotEnoughData);
                }

                // read control info
                let ack_number = SeqNumber::new_truncate(buf.get_u32());
                let full_ack_seq_number = FullAckSeqNumber::new(extra_info);

                let ack = if buf.remaining() < 3 * size_of::<u32>() {
                    Acknowledgement::Lite(ack_number)
                } else {
                    // short/full
                    let rtt = TimeSpan::from_micros(buf.get_i32());
                    let rtt_variance = TimeSpan::from_micros(buf.get_i32());
                    let buffer_available = buf.get_u32();

                    let packet_receive_rate =
                        (buf.remaining() >= size_of::<u32>()).then(|| buf.get_u32());
                    let estimated_link_capacity =
                        (buf.remaining() >= size_of::<u32>()).then(|| buf.get_u32());
                    let data_receive_rate =
                        (buf.remaining() >= size_of::<u32>()).then(|| buf.get_u32());

                    let stats = AckStatistics {
                        rtt,
                        rtt_variance,
                        buffer_available,
                        packet_receive_rate,
                        estimated_link_capacity,
                        data_receive_rate,
                    };

                    match full_ack_seq_number {
                        None => Acknowledgement::Small(ack_number, stats),
                        Some(full_ack) => Acknowledgement::Full(ack_number, stats, full_ack),
                    }
                };
                Ok(ControlTypes::Ack(ack))
            }
            0x3 => {
                // NAK

                let mut loss_info = Vec::new();
                while buf.remaining() >= 4 {
                    loss_info.push(buf.get_u32());
                }

                Ok(ControlTypes::Nak(CompressedLossList(loss_info)))
            }
            0x4 => {
                if buf.remaining() >= 4 {
                    buf.get_u32(); // discard "unused" packet field
                }
                Ok(ControlTypes::CongestionWarning)
            }
            0x5 => {
                if buf.remaining() >= 4 {
                    buf.get_u32(); // discard "unused" packet field
                }
                Ok(ControlTypes::Shutdown)
            }
            0x6 => {
                // ACK2
                if buf.remaining() >= 4 {
                    buf.get_u32(); // discard "unused" packet field
                }
                if let Some(ack_seq_no) = FullAckSeqNumber::new(extra_info) {
                    Ok(ControlTypes::Ack2(ack_seq_no))
                } else {
                    Err(PacketParseError::ZeroAckSequenceNumber)
                }
            }
            0x7 => {
                // Drop request
                if buf.remaining() < 2 * 4 {
                    return Err(PacketParseError::NotEnoughData);
                }

                let start = SeqNumber::new_truncate(buf.get_u32());
                let end = SeqNumber::new_truncate(buf.get_u32());

                Ok(ControlTypes::DropRequest {
                    msg_to_drop: MsgNumber::new_truncate(extra_info as u32), // cast is safe, just reinterpret
                    range: RangeInclusive::new(start, end),
                })
            }
            0x8 => {
                // Peer error
                if buf.remaining() >= 4 {
                    buf.get_u32(); // discard "unused" packet field
                }
                Ok(ControlTypes::PeerError(extra_info))
            }
            0x7FFF => {
                // Srt
                Ok(ControlTypes::Srt(SrtControlPacket::parse(
                    reserved, &mut buf,
                )?))
            }
            x => Err(PacketParseError::BadControlType(x)),
        }
    }

    fn id_byte(&self) -> u16 {
        match *self {
            ControlTypes::Handshake(_) => 0x0,
            ControlTypes::KeepAlive => 0x1,
            ControlTypes::Ack { .. } => 0x2,
            ControlTypes::Nak(_) => 0x3,
            ControlTypes::CongestionWarning => 0x4,
            ControlTypes::Shutdown => 0x5,
            ControlTypes::Ack2(_) => 0x6,
            ControlTypes::DropRequest { .. } => 0x7,
            ControlTypes::PeerError(_) => 0x8,
            ControlTypes::Srt(_) => 0x7FFF,
        }
    }

    fn additional_info(&self) -> u32 {
        match self {
            // These types have additional info
            ControlTypes::DropRequest { msg_to_drop: a, .. } => a.as_raw(),
            ControlTypes::Ack2(a) | ControlTypes::Ack(Acknowledgement::Full(_, _, a)) => {
                (*a).into()
            }
            ControlTypes::PeerError(err) => *err,
            // These do not, just use zero
            ControlTypes::Ack(_)
            | ControlTypes::Handshake(_)
            | ControlTypes::KeepAlive
            | ControlTypes::Nak(_)
            | ControlTypes::CongestionWarning
            | ControlTypes::Shutdown
            | ControlTypes::Srt(_) => 0,
        }
    }

    fn reserved(&self) -> u16 {
        match self {
            ControlTypes::Srt(srt) => srt.type_id(),
            _ => 0,
        }
    }

    fn serialize<T: BufMut>(&self, into: &mut T) {
        match self {
            ControlTypes::Handshake(ref c) => c.serialize(into),
            ControlTypes::Ack(ack) => ack.serialize(into),
            ControlTypes::Nak(ref n) => {
                for loss in n.iter_compressed() {
                    into.put_u32(loss);
                }
            }
            ControlTypes::DropRequest { msg_to_drop, range } => {
                into.put_u32(msg_to_drop.as_raw());
                into.put_u32(range.start().as_raw());
                into.put_u32(range.end().as_raw());
            }
            ControlTypes::CongestionWarning
            | ControlTypes::Ack2(_)
            | ControlTypes::Shutdown
            | ControlTypes::KeepAlive
            | ControlTypes::PeerError(_) => {
                // The reference implementation appends one (4 byte) word at the end of these packets, which wireshark labels as 'Unused'
                // I have no idea why, but wireshark reports it as a "malformed packet" without it. For the record,
                // this is NOT in the UDT specification. I wonder if this was carried over from the original UDT implementation.
                // https://github.com/Haivision/srt/blob/86013826b5e0c4d8e531cf18a30c6ad4b16c1b3b/srtcore/packet.cpp#L309
                into.put_u32(0x0);
            }
            ControlTypes::Srt(srt) => {
                srt.serialize(into);
            }
        };
    }
}

impl Debug for ControlTypes {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            ControlTypes::Handshake(hs) => write!(f, "{:?}", hs),
            ControlTypes::KeepAlive => write!(f, "KeepAlive"),
            ControlTypes::Ack(aci) => write!(f, "{:?}", aci),
            ControlTypes::Nak(nak) => {
                write!(f, "Nak({:?})", nak) // TODO could be better, show ranges
            }
            ControlTypes::CongestionWarning => write!(f, "CongestionWarning"),
            ControlTypes::Shutdown => write!(f, "Shutdown"),
            ControlTypes::Ack2(ackno) => write!(f, "Ack2({})", ackno.0),
            ControlTypes::DropRequest { msg_to_drop, range } => {
                write!(f, "DropReq(msg={} {:?})", msg_to_drop, range)
            }
            ControlTypes::PeerError(e) => write!(f, "PeerError({})", e),
            ControlTypes::Srt(srt) => write!(f, "{:?}", srt),
        }
    }
}

impl CompressedLossList {
    pub fn try_from_iter(iter: impl Iterator<Item = SeqNumber>) -> Option<CompressedLossList> {
        let loss_list = compress_loss_list(iter).collect::<Vec<_>>();
        if loss_list.is_empty() {
            None
        } else {
            Some(CompressedLossList(loss_list))
        }
    }

    pub fn try_from_range(r: Range<SeqNumber>) -> Option<CompressedLossList> {
        if r.is_empty() {
            None
        } else if r.start + 1 == r.end {
            Some(CompressedLossList(vec![r.start.as_raw()]))
        } else {
            Some(CompressedLossList(vec![
                (1 << 31) | r.start.as_raw(),
                (r.end - 1).as_raw(),
            ]))
        }
    }

    pub fn iter_compressed(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().copied()
    }

    pub fn iter_decompressed(&self) -> impl Iterator<Item = SeqNumber> + '_ {
        decompress_loss_list(self.iter_compressed())
    }

    pub fn into_iter_decompressed(self) -> impl Iterator<Item = SeqNumber> {
        decompress_loss_list(self.0.into_iter())
    }
}

impl FromIterator<SeqNumber> for CompressedLossList {
    fn from_iter<T: IntoIterator<Item = SeqNumber>>(iter: T) -> Self {
        Self::try_from_iter(iter.into_iter()).unwrap()
    }
}

impl<'a> FromIterator<&'a SeqNumber> for CompressedLossList {
    fn from_iter<T: IntoIterator<Item = &'a SeqNumber>>(iter: T) -> Self {
        Self::try_from_iter(iter.into_iter().copied()).unwrap()
    }
}

impl From<Range<SeqNumber>> for CompressedLossList {
    fn from(range: Range<SeqNumber>) -> Self {
        Self::try_from_range(range).unwrap()
    }
}

impl Debug for CompressedLossList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter();
        while let Some(a) = iter.next() {
            if a & 0x80000000 != 0 {
                let b = iter.next().expect("Unterminated list");
                write!(f, "{}..={},", a & 0x7fffffff, b)?;
            } else {
                write!(f, "{},", a)?;
            }
        }
        Ok(())
    }
}

impl FullAckSeqNumber {
    pub const INITIAL: FullAckSeqNumber = FullAckSeqNumber(1);

    pub fn new(raw: u32) -> Option<FullAckSeqNumber> {
        if raw == 0 {
            None
        } else {
            Some(FullAckSeqNumber(raw))
        }
    }

    pub fn is_full(&self) -> bool {
        self.0 != 0
    }
}

impl From<FullAckSeqNumber> for u32 {
    fn from(u: FullAckSeqNumber) -> Self {
        u.0
    }
}

impl Add<u32> for FullAckSeqNumber {
    type Output = FullAckSeqNumber;

    fn add(self, rhs: u32) -> Self::Output {
        FullAckSeqNumber(self.0 + rhs)
    }
}

impl Sub<FullAckSeqNumber> for FullAckSeqNumber {
    type Output = usize;

    fn sub(self, rhs: FullAckSeqNumber) -> Self::Output {
        (self.0 - rhs.0).try_into().unwrap()
    }
}

impl Acknowledgement {
    pub fn ack_number(&self) -> SeqNumber {
        match self {
            Acknowledgement::Lite(seq_number)
            | Acknowledgement::Small(seq_number, _)
            | Acknowledgement::Full(seq_number, _, _) => *seq_number,
        }
    }

    pub fn full_ack_seq_number(&self) -> Option<FullAckSeqNumber> {
        match self {
            Acknowledgement::Full(_, _, full_ack_seq_number) => Some(*full_ack_seq_number),
            Acknowledgement::Lite(_) | Acknowledgement::Small(_, _) => None,
        }
    }

    pub fn statistics(&self) -> Option<&AckStatistics> {
        match self {
            Acknowledgement::Small(_, stats) | Acknowledgement::Full(_, stats, _) => Some(stats),
            Acknowledgement::Lite(_) => None,
        }
    }

    pub fn serialize(&self, into: &mut impl BufMut) {
        into.put_u32(self.ack_number().as_raw());
        if let Some(stats) = self.statistics() {
            into.put_i32(stats.rtt.as_micros());
            into.put_i32(stats.rtt_variance.as_micros());
            into.put_u32(stats.buffer_available);

            // Make sure fields are always in the right order
            // Would rather not transmit than transmit incorrectly
            if let Some(prr) = stats.packet_receive_rate {
                into.put_u32(prr);
                if let Some(elc) = stats.estimated_link_capacity {
                    into.put_u32(elc);
                    if let Some(drr) = stats.data_receive_rate {
                        into.put_u32(drr);
                    }
                }
            }
        }
    }

    fn serialized_size(&self) -> usize {
        size_of::<u32>() // ack number
            + self.statistics().map(AckStatistics::serialized_size).unwrap_or(0)
    }
}

impl Debug for HandshakeControlInfo {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "HS {:?} from={:?} {:?}",
            self.shake_type, self.socket_id, self.info
        )
    }
}

impl Debug for HandshakeVsInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeVsInfo::V4(stype) => write!(f, "UDT: {:?}", stype),
            HandshakeVsInfo::V5(hs) => {
                write!(f, "SRT: crypto={:?}", hs.crypto_size)?;
                if let Some(pack) = &hs.ext_hs {
                    write!(f, " hs={:?}", pack)?;
                }
                if let Some(pack) = &hs.ext_km {
                    write!(f, " km={:?}", pack)?;
                }
                if let Some(sid) = &hs.sid {
                    write!(f, " sid={:?}", sid)?;
                }
                Ok(())
            }
        }
    }
}

impl TryFrom<i32> for ShakeType {
    /// Turns an i32 into a `ConnectionType`, returning Err(num) if no valid one was passed.
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ShakeType::Induction),
            0 => Ok(ShakeType::Waveahand),
            -1 => Ok(ShakeType::Conclusion),
            -2 => Ok(ShakeType::Agreement),
            i if i < 1000 => Err(i), // not a basic type and not a rejection code
            i => Ok(ShakeType::Rejection(RejectReason::try_from(i).unwrap())), // unwrap is safe--will always be >= 1000
        }
    }
}

impl From<ShakeType> for i32 {
    fn from(st: ShakeType) -> i32 {
        match st {
            ShakeType::Induction => 1,
            ShakeType::Waveahand => 0,
            ShakeType::Conclusion => -1,
            ShakeType::Agreement => -2,
            ShakeType::Rejection(rej) => rej.into(),
        }
    }
}

/// Returns error if value < 1000
impl TryFrom<i32> for RejectReason {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            v if v < 1000 => Err(v),
            v if v < 2000 => Ok(match CoreRejectReason::try_from(v) {
                Ok(rr) => RejectReason::Core(rr),
                Err(rr) => RejectReason::CoreUnrecognized(rr),
            }),
            v if v < 3000 => Ok(match ServerRejectReason::try_from(v) {
                Ok(rr) => RejectReason::Server(rr),
                Err(rr) => RejectReason::ServerUnrecognized(rr),
            }),
            v => Ok(RejectReason::User(v)),
        }
    }
}

impl From<RejectReason> for i32 {
    fn from(rr: RejectReason) -> i32 {
        match rr {
            RejectReason::Core(c) => c.into(),
            RejectReason::CoreUnrecognized(c) => c,
            RejectReason::Server(s) => s.into(),
            RejectReason::ServerUnrecognized(s) => s,
            RejectReason::User(u) => u,
        }
    }
}

impl Display for RejectReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RejectReason::Core(c) => write!(f, "{}", c),
            RejectReason::CoreUnrecognized(c) => write!(f, "Unrecognized core error: {}", c),
            RejectReason::Server(s) => write!(f, "{}", s),
            RejectReason::ServerUnrecognized(s) => write!(f, "Unrecognized server error: {}", s),
            RejectReason::User(u) => write!(f, "User error: {}", u),
        }
    }
}

impl From<CoreRejectReason> for RejectReason {
    fn from(rr: CoreRejectReason) -> RejectReason {
        RejectReason::Core(rr)
    }
}

impl TryFrom<i32> for CoreRejectReason {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        use CoreRejectReason::*;
        Ok(match value {
            1001 => System,
            1002 => Peer,
            1003 => Resource,
            1004 => Rogue,
            1005 => Backlog,
            1006 => Ipe,
            1007 => Close,
            1008 => Version,
            1009 => RdvCookie,
            1010 => BadSecret,
            1011 => Unsecure,
            1012 => MessageApi,
            1013 => Congestion,
            1014 => Filter,
            1015 => Group,
            1016 => Timeout,
            other => return Err(other),
        })
    }
}

impl From<CoreRejectReason> for i32 {
    fn from(rr: CoreRejectReason) -> i32 {
        rr as i32
    }
}

impl Display for CoreRejectReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CoreRejectReason::System => write!(f, "broken due to system function error"),
            CoreRejectReason::Peer => write!(f, "connection was rejected by peer"),
            CoreRejectReason::Resource => write!(f, "internal problem with resource allocation"),
            CoreRejectReason::Rogue => write!(f, "incorrect data in handshake messages"),
            CoreRejectReason::Backlog => write!(f, "listener's backlog exceeded"),
            CoreRejectReason::Ipe => write!(f, "internal program error"),
            CoreRejectReason::Close => write!(f, "socket is closing"),
            CoreRejectReason::Version => {
                write!(f, "peer is older version than agent's minimum set")
            }
            CoreRejectReason::RdvCookie => write!(f, "rendezvous cookie collision"),
            CoreRejectReason::BadSecret => write!(f, "wrong password"),
            CoreRejectReason::Unsecure => write!(f, "password required or unexpected"),
            CoreRejectReason::MessageApi => write!(f, "streamapi/messageapi collision"),
            CoreRejectReason::Congestion => write!(f, "incompatible congestion-controller type"),
            CoreRejectReason::Filter => write!(f, "incompatible packet filter"),
            CoreRejectReason::Group => write!(f, "incompatible group"),
            CoreRejectReason::Timeout => write!(f, "connection timeout"),
        }
    }
}

impl From<ServerRejectReason> for RejectReason {
    fn from(rr: ServerRejectReason) -> RejectReason {
        RejectReason::Server(rr)
    }
}

impl TryFrom<i32> for ServerRejectReason {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            2000 => ServerRejectReason::Fallback,
            2001 => ServerRejectReason::KeyNotSup,
            2002 => ServerRejectReason::Filepath,
            2003 => ServerRejectReason::HostNotFound,
            2400 => ServerRejectReason::BadRequest,
            2401 => ServerRejectReason::Unauthorized,
            2402 => ServerRejectReason::Overload,
            2403 => ServerRejectReason::Forbidden,
            2404 => ServerRejectReason::Notfound,
            2405 => ServerRejectReason::BadMode,
            2406 => ServerRejectReason::Unacceptable,
            2409 => ServerRejectReason::Conflict,
            2415 => ServerRejectReason::NotSupMedia,
            2423 => ServerRejectReason::Locked,
            2424 => ServerRejectReason::FailedDepend,
            2500 => ServerRejectReason::InternalServerError,
            2501 => ServerRejectReason::Unimplemented,
            2502 => ServerRejectReason::Gateway,
            2503 => ServerRejectReason::Down,
            2505 => ServerRejectReason::Version,
            2507 => ServerRejectReason::NoRoom,
            unrecog => return Err(unrecog),
        })
    }
}

impl From<ServerRejectReason> for i32 {
    fn from(rr: ServerRejectReason) -> i32 {
        rr as i32
    }
}

impl Display for ServerRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRejectReason::Fallback =>
                write!(f, "the application wants to report some problem, but can't precisely specify it"),
            ServerRejectReason::KeyNotSup =>
                write!(f, "The key used in the StreamID keyed string is not supported by the service"),
            ServerRejectReason::Filepath =>write!(f, "The resource type designates a file and the path is either wrong syntax or not found"),
            ServerRejectReason::HostNotFound => write!(f, "The `h` host specification was not recognized by the service"),
            ServerRejectReason::BadRequest => write!(f, "General syntax error in the SocketID specification (also a fallback code for undefined cases)"),
            ServerRejectReason::Unauthorized => write!(f, "Authentication failed, provided that the user was correctly identified and access to the required resource would be granted"),
            ServerRejectReason::Overload => write!(f, "The server is too heavily loaded, or you have exceeded credits for accessing the service and the resource"),
            ServerRejectReason::Forbidden => write!(f, "Access denied to the resource by any kind of reason"),
            ServerRejectReason::Notfound => write!(f, "Resource not found at this time"),
            ServerRejectReason::BadMode => write!(f, "The mode specified in `m` key in StreamID is not supported for this request"),
            ServerRejectReason::Unacceptable => write!(f, "The requested parameters specified in SocketID cannot be satisfied for the requested resource. Also when m=publish and the data format is not acceptable"),
            ServerRejectReason::Conflict => write!(f, "The resource being accessed is already locked for modification. This is in case of m=publish and the specified resource is currently read-only"),
            ServerRejectReason::NotSupMedia => write!(f, "The media type is not supported by the application. This is the `t` key that specifies the media type as stream, file and auth, possibly extended by the application"),
            ServerRejectReason::Locked => write!(f, "The resource being accessed is locked for any access"),
            ServerRejectReason::FailedDepend => write!(f, "The request failed because it specified a dependent session ID that has been disconnected"),
            ServerRejectReason::InternalServerError => write!(f, "Unexpected internal server error"),
            ServerRejectReason::Unimplemented => write!(f, "The request was recognized, but the current version doesn't support it (unimplemented)"),
            ServerRejectReason::Gateway => write!(f, "The server acts as a gateway and the target endpoint rejected the connection"),
            ServerRejectReason::Down => write!(f, "The service has been temporarily taken over by a stub reporting this error. The real service can be down for maintenance or crashed"),
            ServerRejectReason::Version => write!(f, "SRT version not supported. This might be either unsupported backward compatibility, or an upper value of a version"),
            ServerRejectReason::NoRoom => write!(f, "The data stream cannot be archived due to lacking storage space. This is in case when the request type was to send a file or the live stream to be archived"),
        }
    }
}

impl HandshakeControlInfo {
    fn serialized_size(&self) -> usize {
        8 * size_of::<u32>() +  // version/cookie/etc
        size_of::<u128>() + // ip address
        match &self.info {
            HandshakeVsInfo::V4(_) => 0,
            HandshakeVsInfo::V5(info) => {
                info.ext_hs.as_ref().map(|hs| 2 * size_of::<u16>() + usize::from(hs.size_words()) * size_of::<u32>()).unwrap_or(0)
                +
                info.ext_km.as_ref().map(|hs| 2 * size_of::<u16>() + usize::from(hs.size_words()) * size_of::<u32>()).unwrap_or(0)
                +
                info.sid.as_ref().map(|sid| 2 * size_of::<u16>() + ((sid.len() + 3) / 4 * 4)).unwrap_or(0)
            }
        }
    }

    fn serialize(&self, into: &mut impl BufMut) {
        into.put_u32(self.info.version());
        into.put_u32(self.info.type_flags(self.shake_type));
        into.put_u32(self.init_seq_num.as_raw());
        into.put_u32(self.max_packet_size);
        into.put_u32(self.max_flow_size);
        into.put_i32(self.shake_type.into());
        into.put_u32(self.socket_id.0);
        into.put_i32(self.syn_cookie);

        match self.peer_addr {
            IpAddr::V4(four) => {
                let v = u32::from(four);
                into.put_u32_le(v);

                // the data structure reuiqres enough space for an ipv6, so pad the end with 16 - 4 = 12 bytes
                into.put(&[0; 12][..]);
            }
            IpAddr::V6(six) => {
                let v = u128::from(six);

                into.put_u128(v);
            }
        }

        // serialzie extensions
        if let HandshakeVsInfo::V5(hs) = &self.info {
            for ext in IntoIter::new([
                &hs.ext_hs,
                &hs.ext_km,
                &hs.sid.clone().map(SrtControlPacket::StreamId),
            ])
            .filter_map(|s| s.as_ref())
            {
                into.put_u16(ext.type_id());
                // put the size in 32-bit integers
                into.put_u16(ext.size_words());
                ext.serialize(into);
            }
        }
    }
}

impl AckStatistics {
    fn serialized_size(&self) -> usize {
        size_of::<u32>()
            * (3 + match self {
                Self {
                    packet_receive_rate: None,
                    ..
                } => 0,
                Self {
                    estimated_link_capacity: None,
                    ..
                } => 1,
                Self {
                    data_receive_rate: None,
                    ..
                } => 2,
                _ => 3,
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{array::IntoIter, time::Duration};
    use std::{convert::TryInto, io::Cursor};

    use crate::options::*;

    fn ser_des_test(pack: ControlPacket) -> Vec<u8> {
        let mut buf = vec![];
        pack.serialize(&mut buf);

        let mut cursor = Cursor::new(&buf);
        let des = ControlPacket::parse(&mut cursor, false).unwrap();
        assert_eq!(cursor.remaining(), 0);
        assert_eq!(pack, des);
        assert_eq!(
            pack.wire_size(),
            buf.len() + 28,
            "Packet {:?} wrong wire size",
            pack
        ); // 28 is is IP+UDP buffer

        buf
    }

    #[test]
    fn lite_ack_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(1234),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Ack(Acknowledgement::Lite(SeqNumber::new_truncate(1234))),
        });
    }

    #[test]
    fn handshake_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber::new_truncate(1_827_131),
                max_packet_size: 1500,
                max_flow_size: 25600,
                shake_type: ShakeType::Conclusion,
                socket_id: SocketId(1231),
                syn_cookie: 0,
                peer_addr: "127.0.0.1".parse().unwrap(),
                info: HandshakeVsInfo::V5(HsV5Info {
                    crypto_size: 0, // TODO: implement
                    ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                        version: SrtVersion::CURRENT,
                        flags: SrtShakeFlags::NAKREPORT | SrtShakeFlags::TSBPDSND,
                        send_latency: Duration::from_millis(3000),
                        recv_latency: Duration::from_millis(12345),
                    })),
                    ext_km: None,
                    ext_group: None,
                    sid: None,
                }),
            }),
        });
    }

    #[test]
    fn ack_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(113_703),
            dest_sockid: SocketId(2_453_706_529),
            control_type: ControlTypes::Ack(Acknowledgement::Full(
                SeqNumber::new_truncate(282_049_186),
                AckStatistics {
                    rtt: TimeSpan::from_micros(10_002),
                    rtt_variance: TimeSpan::from_micros(1000),
                    buffer_available: 1314,
                    packet_receive_rate: Some(0),
                    estimated_link_capacity: Some(0),
                    data_receive_rate: Some(0),
                },
                FullAckSeqNumber::new(1).unwrap(),
            )),
        });
    }

    #[test]
    fn ack2_ser_des_test() {
        let buf = ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(125_812),
            dest_sockid: SocketId(8313),
            control_type: ControlTypes::Ack2(FullAckSeqNumber::new(831).unwrap()),
        });

        // dword 2 should have 831 in big endian, so the last two bits of the second dword
        assert_eq!((u32::from(buf[6]) << 8) + u32::from(buf[7]), 831);
    }

    #[test]
    fn enc_size_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber(0),
                max_packet_size: 1816,
                max_flow_size: 0,
                shake_type: ShakeType::Conclusion,
                socket_id: SocketId(0),
                syn_cookie: 0,
                peer_addr: [127, 0, 0, 1].into(),
                info: HandshakeVsInfo::V5(HsV5Info {
                    crypto_size: 16,
                    ext_km: None,
                    ext_hs: None,
                    ext_group: None,
                    sid: None,
                }),
            }),
        });
    }

    #[test]
    fn sid_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber(0),
                max_packet_size: 1816,
                max_flow_size: 0,
                shake_type: ShakeType::Conclusion,
                socket_id: SocketId(0),
                syn_cookie: 0,
                peer_addr: [127, 0, 0, 1].into(),
                info: HandshakeVsInfo::V5(HsV5Info {
                    crypto_size: 0,
                    ext_km: None,
                    ext_hs: None,
                    ext_group: None,
                    sid: Some("Hello hello".into()),
                }),
            }),
        });
    }

    #[test]
    fn keepalive_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::KeepAlive,
        });
    }

    #[test]
    fn congestion_warning_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(100),
            dest_sockid: rand::random(),
            control_type: ControlTypes::CongestionWarning,
        });
    }

    #[test]
    fn peer_error_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(100),
            dest_sockid: rand::random(),
            control_type: ControlTypes::PeerError(1234),
        });
    }

    #[test]
    fn congestion_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(100),
            dest_sockid: rand::random(),
            control_type: ControlTypes::Srt(SrtControlPacket::Congestion("live".to_string())),
        });
    }

    #[test]
    fn group_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(100),
            dest_sockid: rand::random(),
            control_type: ControlTypes::Srt(SrtControlPacket::Group {
                ty: GroupType::MainBackup,
                flags: GroupFlags::MSG_SYNC,
                weight: 123,
            }),
        });
    }

    #[test]
    fn filter_ser_des_test() {
        ser_des_test(ControlPacket {
            timestamp: TimeStamp::from_micros(100),
            dest_sockid: rand::random(),
            control_type: ControlTypes::Srt(SrtControlPacket::Filter(FilterSpec(
                IntoIter::new([("hi".to_string(), "bye".to_string())]).collect(),
            ))),
        });
    }

    #[test]
    fn raw_srt_packet_test() {
        // this was taken from wireshark on a packet from stransmit that crashed
        // it is a SRT reject message
        let packet_data =
            hex::decode("FFFF000000000000000189702BFFEFF2000103010000001E00000078").unwrap();

        let packet = ControlPacket::parse(&mut Cursor::new(packet_data), false).unwrap();

        assert_eq!(
            packet,
            ControlPacket {
                timestamp: TimeStamp::from_micros(100_720),
                dest_sockid: SocketId(738_193_394),
                control_type: ControlTypes::Srt(SrtControlPacket::Reject)
            }
        )
    }

    #[test]
    fn raw_handshake_ipv6() {
        let packet_data = hex::decode("8000000000000000000002b00000000000000004000000023c3b0296000005dc00002000000000010669ead20000000000000000000000000000000001000000").unwrap();
        let packet = ControlPacket::parse(&mut Cursor::new(&packet_data[..]), true).unwrap();

        let r = ControlPacket {
            timestamp: TimeStamp::from_micros(688),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber(1010500246),
                max_packet_size: 1500,
                max_flow_size: 8192,
                shake_type: ShakeType::Induction,
                socket_id: SocketId(0x0669EAD2),
                syn_cookie: 0,
                peer_addr: "::1.0.0.0".parse().unwrap(),
                info: HandshakeVsInfo::V4(SocketType::Datagram),
            }),
        };

        assert_eq!(packet, r);

        // reserialize it
        let mut buf = vec![];
        packet.serialize(&mut buf);

        assert_eq!(&buf[..], &packet_data[..]);
    }

    #[test]
    fn raw_handshake_srt() {
        // this is a example HSv5 conclusion packet from the reference implementation
        let packet_data = hex::decode("8000000000000000000F9EC400000000000000050000000144BEA60D000005DC00002000FFFFFFFF3D6936B6E3E405DD0100007F00000000000000000000000000010003000103010000002F00780000").unwrap();
        let packet = ControlPacket::parse(&mut Cursor::new(&packet_data[..]), false).unwrap();
        assert_eq!(
            packet,
            ControlPacket {
                timestamp: TimeStamp::from_micros(1_023_684),
                dest_sockid: SocketId(0),
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num: SeqNumber(1_153_345_037),
                    max_packet_size: 1500,
                    max_flow_size: 8192,
                    shake_type: ShakeType::Conclusion,
                    socket_id: SocketId(1_030_305_462),
                    syn_cookie: -471_595_555,
                    peer_addr: "127.0.0.1".parse().unwrap(),
                    info: HandshakeVsInfo::V5(HsV5Info {
                        crypto_size: 0,
                        ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                            version: SrtVersion::new(1, 3, 1),
                            flags: SrtShakeFlags::TSBPDSND
                                | SrtShakeFlags::TSBPDRCV
                                | SrtShakeFlags::HAICRYPT
                                | SrtShakeFlags::TLPKTDROP
                                | SrtShakeFlags::REXMITFLG,
                            send_latency: Duration::from_millis(120),
                            recv_latency: Duration::new(0, 0)
                        })),
                        ext_km: None,
                        ext_group: None,
                        sid: None,
                    })
                })
            }
        );

        // reserialize it
        let mut buf = vec![];
        packet.serialize(&mut buf);

        assert_eq!(&buf[..], &packet_data[..]);
    }

    #[test]
    fn raw_handshake_sid() {
        // this is an example HSv5 conclusion packet from the reference implementation that has a
        // stream id.
        let packet_data = hex::decode("800000000000000000000b1400000000000000050000000563444b2e000005dc00002000ffffffff37eb0ee52154fbd60100007f0000000000000000000000000001000300010401000000bf0014001400050003646362616867666500006a69").unwrap();
        let packet = ControlPacket::parse(&mut Cursor::new(&packet_data[..]), false).unwrap();
        assert_eq!(
            packet,
            ControlPacket {
                timestamp: TimeStamp::from_micros(2836),
                dest_sockid: SocketId(0),
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num: SeqNumber(1_665_420_078),
                    max_packet_size: 1500,
                    max_flow_size: 8192,
                    shake_type: ShakeType::Conclusion,
                    socket_id: SocketId(0x37eb0ee5),
                    syn_cookie: 559_217_622,
                    peer_addr: "127.0.0.1".parse().unwrap(),
                    info: HandshakeVsInfo::V5(HsV5Info {
                        crypto_size: 0,
                        ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                            version: SrtVersion::new(1, 4, 1),
                            flags: SrtShakeFlags::TSBPDSND
                                | SrtShakeFlags::TSBPDRCV
                                | SrtShakeFlags::HAICRYPT
                                | SrtShakeFlags::REXMITFLG
                                | SrtShakeFlags::TLPKTDROP
                                | SrtShakeFlags::NAKREPORT
                                | SrtShakeFlags::PACKET_FILTER,
                            send_latency: Duration::from_millis(20),
                            recv_latency: Duration::from_millis(20)
                        })),
                        ext_km: None,
                        ext_group: None,
                        sid: Some(String::from("abcdefghij")),
                    })
                })
            }
        );

        // reserialize it
        let mut buf = vec![];
        packet.serialize(&mut buf);

        assert_eq!(&buf[..], &packet_data[..]);
    }

    #[test]
    fn raw_handshake_crypto() {
        // this is an example HSv5 conclusion packet from the reference implementation that has crypto data embedded.
        let packet_data = hex::decode("800000000000000000175E8A0000000000000005000000036FEFB8D8000005DC00002000FFFFFFFF35E790ED5D16CCEA0100007F00000000000000000000000000010003000103010000002F01F401F40003000E122029010000000002000200000004049D75B0AC924C6E4C9EC40FEB4FE973DB1D215D426C18A2871EBF77E2646D9BAB15DBD7689AEF60EC").unwrap();
        let packet = ControlPacket::parse(&mut Cursor::new(&packet_data[..]), false).unwrap();

        assert_eq!(
            packet,
            ControlPacket {
                timestamp: TimeStamp::from_micros(1_531_530),
                dest_sockid: SocketId(0),
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num: SeqNumber(1_877_981_400),
                    max_packet_size: 1_500,
                    max_flow_size: 8_192,
                    shake_type: ShakeType::Conclusion,
                    socket_id: SocketId(904_368_365),
                    syn_cookie: 1_561_775_338,
                    peer_addr: "127.0.0.1".parse().unwrap(),
                    info: HandshakeVsInfo::V5(HsV5Info {
                        crypto_size: 0,
                        ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                            version: SrtVersion::new(1, 3, 1),
                            flags: SrtShakeFlags::TSBPDSND
                                | SrtShakeFlags::TSBPDRCV
                                | SrtShakeFlags::HAICRYPT
                                | SrtShakeFlags::TLPKTDROP
                                | SrtShakeFlags::REXMITFLG,
                            send_latency: Duration::from_millis(500),
                            recv_latency: Duration::from_millis(500)
                        })),
                        ext_km: Some(SrtControlPacket::KeyRefreshRequest(KeyingMaterialMessage {
                            pt: PacketType::KeyingMaterial,
                            key_flags: KeyFlags::EVEN,
                            keki: 0,
                            cipher: CipherType::Ctr,
                            auth: Auth::None,
                            salt: hex::decode("9D75B0AC924C6E4C9EC40FEB4FE973DB").unwrap(),
                            wrapped_keys: hex::decode(
                                "1D215D426C18A2871EBF77E2646D9BAB15DBD7689AEF60EC"
                            )
                            .unwrap()
                        })),
                        ext_group: None,
                        sid: None,
                    })
                })
            }
        );

        let mut buf = vec![];
        packet.serialize(&mut buf);

        assert_eq!(&buf[..], &packet_data[..])
    }

    #[test]
    fn raw_handshake_crypto_pt2() {
        let packet_data = hex::decode("8000000000000000000000000C110D94000000050000000374B7526E000005DC00002000FFFFFFFF18C1CED1F3819B720100007F00000000000000000000000000020003000103010000003F03E803E80004000E12202901000000000200020000000404D3B3D84BE1188A4EBDA4DA16EA65D522D82DE544E1BE06B6ED8128BF15AA4E18EC50EAA95546B101").unwrap();
        let _packet = ControlPacket::parse(&mut Cursor::new(&packet_data[..]), false).unwrap();
        dbg!(&_packet);
    }

    #[test]
    fn short_ack() {
        // this is a packet received from the reference implementation that crashed the parser
        let packet_data =
            hex::decode("800200000000000e000246e5d96d5e1a389c24780000452900007bb000001fa9")
                .unwrap();

        let _cp = ControlPacket::parse(&mut Cursor::new(packet_data), false).unwrap();
    }

    #[test]
    fn test_reject_reason_deser_ser() {
        assert_eq!(
            Ok(RejectReason::Server(ServerRejectReason::Unimplemented)),
            <i32 as TryInto<RejectReason>>::try_into(
                RejectReason::Server(ServerRejectReason::Unimplemented).into()
            )
        );
    }

    #[test]
    fn test_unordered_hs_extensions() {
        //Taken from Wireshark dump of FFMPEG connection handshake
        let packet_data = hex::decode(concat!(
            "80000000000000000000dea800000000",
            "000000050004000751dca3b8000005b8",
            "00002000ffffffff025c84b8da7ee4e7",
            "0100007f000000000000000000000000",
            "0001000300010402000000bf003c003c",
            "000500033a3a212365683d7500000078",
            "00030012122029010000000002000200",
            "00000408437937d8c23ce2090754c5a7",
            "a9e608c14631aef7ac0b8a46b77b8c0b",
            "97d4061e565dcb86e4c5cc3701e1f992",
            "a5b2de3651c937c94f3333a6"
        ))
        .unwrap();

        let packet = ControlPacket::parse(&mut Cursor::new(packet_data), false).unwrap();
        let reference = ControlPacket {
            timestamp: TimeStamp::from_micros(57000),
            dest_sockid: SocketId(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: SeqNumber(1373414328),
                max_packet_size: 1464,
                max_flow_size: 8192,
                shake_type: ShakeType::Conclusion,
                socket_id: SocketId(0x025C84B8),
                syn_cookie: 0xda7ee4e7u32 as i32,
                peer_addr: [127, 0, 0, 1].into(),
                info: HandshakeVsInfo::V5(HsV5Info {
                    crypto_size: 32,
                    ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                        version: SrtVersion::new(1, 4, 2),
                        flags: SrtShakeFlags::TSBPDSND
                            | SrtShakeFlags::TSBPDRCV
                            | SrtShakeFlags::HAICRYPT
                            | SrtShakeFlags::TLPKTDROP
                            | SrtShakeFlags::NAKREPORT
                            | SrtShakeFlags::REXMITFLG
                            | SrtShakeFlags::PACKET_FILTER,
                        send_latency: Duration::from_millis(60),
                        recv_latency: Duration::from_millis(60)
                    })),
                    ext_km: Some(SrtControlPacket::KeyRefreshRequest(KeyingMaterialMessage {
                        pt: PacketType::KeyingMaterial,
                        key_flags: KeyFlags::EVEN,
                        keki: 0,
                        cipher: CipherType::Ctr,
                        auth: Auth::None,
                        salt: hex::decode("437937d8c23ce2090754c5a7a9e608c1").unwrap(),
                        wrapped_keys: hex::decode(
                            "4631aef7ac0b8a46b77b8c0b97d4061e565dcb86e4c5cc3701e1f992a5b2de3651c937c94f3333a6"
                        )
                            .unwrap()
                    })),
                    ext_group: None,
                    sid: Some("#!::u=hex".into()),
                }),
            }),
        };

        assert_eq!(packet, reference);
    }
}
