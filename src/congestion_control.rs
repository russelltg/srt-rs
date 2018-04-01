use std::time::Duration;

use srt_object::SrtObject;

/// Timer variables to be manipulated by CC
pub struct CCVariables {
    /// Inter-packet interval
    pub send_interval: Duration,

    /// Window size
    pub window_size: i32,

    /// The number of wait for before an ACK
    /// if -1, then time based ACK is used
    pub ack_interval: i32,

    /// The time between ACKs. Used if ack_interval is -1 (TODO: i think?)
    pub ack_timer: Duration,

    /// TODO: literally no clue what this is used for
    pub rto: i32,
}


pub trait CongestionControl<T>
    where T: SrtObject {

    /// When the socket is connected
    fn init(&mut self, srt: &T, vars: &mut CCVariables);

    /// When the socket is closed
    fn close(&mut self, srt: &T, vars: &mut CCVariables);

    /// When an ACK packet is received
    fn on_ack(&mut self, srt: &T, vars: &mut CCVariables);

    /// When a NAK packet is received
    fn on_nak(&mut self, srt: &T, vars: &mut CCVariables);

    /// When a timeout occurs TODO: when is this? isn't this sender-only?
    fn on_timeout(&mut self, srt: &T, vars: &mut CCVariables);

    /// On packet sent
    fn on_packet_sent(&mut self, srt: &T, vars: &mut CCVariables);

    /// When a packet is received TODO: same question
    fn on_packet_recv(&mut self, srt: &T, vars: &mut CCVariables);
}
