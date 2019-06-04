/// Statistics that SRT can capture on
#[derive(Debug, Copy, Clone)]
pub struct Stats {
    /// Timestamp that the stats was captured, in us from socket start
    pub timestamp: u64,

    /// Round trip time, in us
    pub rtt: i32,

    /// Round trip average variance, in us
    pub rtt_var: i32,

    /// Flow window size
    pub flow_size: u32,

    /// SND time
    /// The time between sending each packet, in us
    pub snd: i32,

    /// The number of packets received in time, retransmitted or not
    pub received_packets: u32,

    /// The number of packets that have been retransmitted but still received in time
    pub retransmitted_packets: u32,

    /// The number of bytes in the sender buffer waiting to be sent
    pub sender_buffer: u32,

    /// The number of permanatly lost packets; always zero when not in SRT mode
    pub lost_packets: u32,

    /// Estimated link capacity, in bps
    pub est_link_cap: i32,
}
