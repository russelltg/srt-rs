use crate::SeqNumber;
use std::time::Duration;

/// Defines all the data that CC algorithms need
pub struct CCData {
    /// Round trip time
    pub rtt: Duration,

    /// The max segment size, in bytes
    pub max_segment_size: u32,

    /// Estimated bandwidth, in bytes/sec
    pub est_bandwidth: i32,

    /// The latest sequence number to be sent, sender only
    pub latest_seq_num: Option<SeqNumber>,

    /// The packet arrival rate, both sender and receiver, as
    /// the receiver sends this info to the sender in ACK packets
    pub packet_arr_rate: u32,
}
