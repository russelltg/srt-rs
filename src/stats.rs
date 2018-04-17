use std::time::Duration;

/// Statistics that SRT can capture on
pub struct Stats {
    /// Round trip time
    pub rtt: Duration,

    /// Flow window size
    pub flow_size: i32,

    /// SND time
    /// The time between sending each packet
    pub snd: Duration,

    /// The number of lost packets
    pub lost_packets: i32,

    /// Estimated link capacity, in bps
    pub est_link_cap: i32,
}
