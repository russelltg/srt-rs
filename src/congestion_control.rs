use std::time::Duration;

/// State variables to be passed to CC algos
pub struct CCState {
    rtt: Duration,
    max_packet_size: i32,
    est_bandwidth: i32,

    /// The latest sequence number that's been sent
    latest_seq_num: i32,

    /// Packet arrival rate of the receiver, in packets/sec
    packet_arr_rate: i32,
}

/// Timer variables to be manipulated by CC
pub struct CCVariables {
    /// The number of wait for before an ACK
    /// if -1, then time based ACK is used
    ack_interval: i32,

    /// The time between ACKs. Used if ack_interval is -1 (TODO: i think?)
    ack_timer: Duration,

    /// TODO: literally no clue what this is used for
    rto: i32

}


pub trait CongestionControl {
    /// When the socket is connected
    fn init(&mut self, state: &CCState, vars: &mut CCVariables);

    /// When the scoket is closed
    fn close(&mut self, state: &CCState, vars: &mut CCVariables);

    /// When an ACK packet is received
    fn on_ack(&mut self, state: &CCState, vars: &mut CCVariables);

    /// When a NAK packet is received
    fn on_nak(&mut self, state: &CCState, vars: &mut CCVariables);

    /// When a timeout occurs TODO: when is this? isn't this sender-only?
    fn on_timeout(&mut self, state: &CCState, vars: &mut CCVariables);

    /// On packet sent
    fn on_packet_sent(&mut self, state: &CCState, vars: &mut CCVariables);

    /// When a packet is received TODO: same question
    fn on_packet_recv(&mut self, state: &CCState, vars: &mut CCVariables);
}
