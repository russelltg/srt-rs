use std::time::Duration;

/// Congestion control trait, sender side
///
/// Used to define custom congestion control
pub trait SenderCongestionCtrl {
    /// When an ACK packet is received
    fn on_ack(&mut self, data: &CCData);

    /// When a NAK packet is received
    fn on_nak(&mut self, data: &CCData);

    /// On packet sent
    fn on_packet_sent(&mut self, data: &CCData);

    /// Get the interval between sending packets
    fn send_interval(&self) -> Duration;

    /// Get the window size
    /// This is the number of packets to wait for before ACK
    fn window_size(&self) -> i32;
}

/// Congestion control trait, receiver side
pub trait RecvrCongestionCtrl {

    /// When a timeout occurs on the receiver
    fn on_timeout(&mut self, data: &CCData);

    /// When a packet is received by the receiver
    fn on_packet_recvd(&mut self, data: &CCData);

    /// Get the ACK mode
    fn ack_mode(&self) -> AckMode;
}

/// Defines all the data that CC algorithms need
pub struct CCData {

    /// Round trip time
    pub rtt: Duration,

    /// The max segment size, in bytes
    pub max_segment_size: usize,

    /// Estimated bandwidth, in bytes/sec
    pub est_bandwidth: i32,

    /// The latest sequence number to be sent, sender only
    pub latest_seq_num: Option<i32>,

    /// The packet arrival rate, receiver only
    pub packet_arr_rate: Option<i32>,

}

/// Defines the different kinds of deciding when to send an ACK packet
pub enum AckMode {
    /// Send an ACK packet every duration
    Timer(Duration),
    /// Send an ACK packet after a certain number of packets
    PacketCount(i32),
}
