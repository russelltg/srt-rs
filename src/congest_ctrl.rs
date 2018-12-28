use crate::SeqNumber;
use std::time::Duration;

/// Congestion control trait, sender side
///
/// Used to define custom congestion control
pub trait CongestCtrl {
    fn init(&mut self, _init_seq_num: SeqNumber) {}

    /// When an ACK packet is received
    fn on_ack(&mut self, _data: &CCData) {}

    /// When a NAK packet is received
    fn on_nak(&mut self, _largest_seq_in_ll: SeqNumber, _data: &CCData) {}

    /// On packet sent
    fn on_packet_sent(&mut self, _data: &CCData) {}

    /// Get the interval between sending packets
    fn send_interval(&self) -> Duration;

    /// Get the window size
    /// This is the number of packets to wait for before ACK
    fn window_size(&self) -> u32;
}

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
    pub packet_arr_rate: i32,
}
