/// Statistics that SRT can capture on
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Stats {
    /// Timestamp that the stats was captured, in us from socket start
    pub timestamp: i32,

    /// Round trip time, in us
    pub rtt: i32,

    /// Flow window size
    pub flow_size: i32,

    /// SND time
    /// The time between sending each packet, in us
    pub snd: i32,

    /// The number of lost packets
    pub lost_packets: i32,

    /// Estimated link capacity, in bps
    pub est_link_cap: i32,
}
