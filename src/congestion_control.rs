use std::time::Duration;

use srt_object::SrtObject;

/// Congestion control trait
///
/// Used to define custom congestion control
/// TODO: should this be split into sender and receiver side?
pub trait CongestionControl {
    /// When an ACK packet is received
    fn on_ack(&mut self, srt: &SrtObject);

    /// When a NAK packet is received
    fn on_nak(&mut self, srt: &SrtObject);

    /// When a timeout occurs on the receiver
    fn on_timeout(&mut self, srt: &SrtObject);

    /// On packet sent
    fn on_packet_sent(&mut self, srt: &SrtObject);

    /// When a packet is received by the receiver
    fn on_packet_recvd(&mut self, srt: &SrtObject);

    /// Get the interval between sending packets
    fn send_interval(&self) -> Duration;

    /// Get the window size
    /// This is the number of packets to wait for before ACK
    fn window_size(&self) -> i32;

    /// Get the ACK mode
    fn ack_mode(&self) -> AckMode;
}

/// Defines all the data that CC algorithms need
pub struct CCData {
//1) RTT
//2) Maximum Segment/Packet Size
//3) Estimated Bandwidth
//4) The latest packet sequence number that has been sent so far
//5) Packet arriving rate at the receiver side

    /// Round trip time
    pub rtt: Duration,

    /// The max segment size, in bytes
    pub max_segment_size: usize,

    /// Estimated bandwidth, in bytes/sec
    pub est_bandwidth: i32,

    /// The packet data, depends on if it's a receiver or not
    pub packet_data: CCPacketData,

}

pub enum CCPacketData {

    /// If this is the sender, it's the sequence number of the latest packet sent
    Sender(i32),

    /// If this is the receiver, this is the Packet arrival rate
    Receiver(i32),
}

/// Defines the different kinds of deciding when to send an ACK packet
pub enum AckMode {
    /// Send an ACK packet every duration
    Timer(Duration),
    /// Send an ACK packet after a certain number of packets
    PacketCount(i32),
}
