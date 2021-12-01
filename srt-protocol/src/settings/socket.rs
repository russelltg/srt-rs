/*
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ConnectionSettings {
    /// The local UDT socket id
    pub local_sockid: SocketId,

    pub cipher: Option<CipherSettings>,
    pub stream_id: Option<String>,
}
*/

pub use crate::packet::SeqNumber;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use crate::protocol::handshake::Handshake;
use crate::protocol::time::Rtt;
use crate::settings::{KeyOptions, StreamEncryptionKeys};
use super::SocketId;

pub struct SocketSettings {
    /// The remote socket to send & receive to
    pub remote_socket: SocketAddr,

    /// The socket id of the UDT entity on the other side
    pub remote_socket_id: SocketId,

    /// The first sequence number that will be sent/received
    pub init_seq_num: SeqNumber,

    /// The time that this socket started at, used to develop timestamps
    /// This is precisely the time that the Initiator sends the first
    /// packet (or an approximation if not the initiator, assuming
    /// symmetrical latency)
    pub socket_start_time: Instant,

    /// canned handshake reply, to ensure handshakes eventually converge
    pub handshake: Handshake,

    pub encryption: Option<EncryptionSettings>,
}

pub struct EncryptionSettings {
    pub key_options: KeyOptions,
    pub stream_keys: StreamEncryptionKeys,
}

struct SenderSettings {
    pub tsbpd_latency: Duration,
    pub max_flow_size: u32,
    /// The maximum packet size
    pub max_packet_size: usize,
    /// buffer size in packets
    pub buffer_size: usize,
}

pub struct ReceiverSettings {
    pub tsbpd_latency: Duration,
    /// the initial RTT, to be used with TSBPD
    pub rtt: Rtt,
    /// buffer size in packets
    pub buffer_size: usize,
}