use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::protocol::handshake::Handshake;
use crate::{crypto::CryptoManager, SeqNumber, SocketID};

#[derive(Clone, Debug)]
pub struct Connection {
    pub settings: ConnectionSettings,
    pub handshake: Handshake,
}

#[derive(Debug, Clone)]
pub struct ConnectionSettings {
    /// The remote socket to send & receive to
    pub remote: SocketAddr,

    /// The socket id of the UDT entity on the other side
    pub remote_sockid: SocketID,

    /// The local UDT socket id
    pub local_sockid: SocketID,

    /// The time that this socket started at, used to develop timestamps
    pub socket_start_time: Instant,

    /// The first sequence number that will be sent/received
    pub init_send_seq_num: SeqNumber,
    pub init_recv_seq_num: SeqNumber,

    /// The maximum packet size
    pub max_packet_size: u32,

    /// The maxiumum flow size
    pub max_flow_size: u32,

    /// The TSBPD of the connection--the max of each side's repspective latencies
    pub send_tsbpd_latency: Duration,
    pub recv_tsbpd_latency: Duration,

    // if this stream is encrypted, it needs a crypto manager
    pub crypto_manager: Option<CryptoManager>,

    pub stream_id: Option<String>,
}

impl ConnectionSettings {
    /// Timestamp in us
    pub fn get_timestamp(&self, at: Instant) -> i32 {
        let elapsed = at - self.socket_start_time;

        elapsed.as_micros() as i32 // TODO: handle overflow here
    }

    /// Timestamp in us
    pub fn get_timestamp_now(&self) -> i32 {
        self.get_timestamp(Instant::now())
    }
}
