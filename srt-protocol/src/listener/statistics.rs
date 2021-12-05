#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListenerStatistics {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_parse_errors: u64,
    pub rx_io_errors: u64,

    pub tx_packets: u64,
    pub tx_bytes: u64,

    pub delegated_packets: u64,
    pub delegated_bytes: u64,

    pub cx_inbound: u64,
    pub cx_opened: u64,
    pub cx_dropped: u64,
    pub cx_rejected: u64,
    pub cx_accepted: u64,
}
