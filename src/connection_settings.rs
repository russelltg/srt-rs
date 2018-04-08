use std::{
    time::Instant,
    net::SocketAddr,
};

use {SocketID, SeqNumber};

#[derive(Clone, Copy)]
pub struct ConnectionSettings {

    /// The remote socket to send & receive to
    pub remote: SocketAddr,

    /// The socket id of the UDT entity on the other side
    pub remote_sockid: SocketID,

    /// The local UDT socket id
    pub local_sockid: SocketID,

    /// The time that this socket started at, used to develop timestamps
    pub socket_start_time: Instant,

    /// The first sequence number
    pub init_seq_num: SeqNumber,

    /// The maximum packet size
    pub max_packet_size: i32,

    /// The maxiumum flow size
    pub max_flow_size: i32,
}

impl ConnectionSettings {

    /// Timestamp in us
    pub fn get_timestamp(&self) -> i32 {
        let elapsed = self.socket_start_time.elapsed();

        (elapsed.as_secs() * 1_000_000 + (u64::from(elapsed.subsec_nanos()) / 1_000)) as i32
    }
}
