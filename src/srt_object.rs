use std::time::{Instant, Duration};

/// A generic SRT object, defining things any SRT object (sender or receiver) should do
pub trait SrtObject {

    /// The packet arrival rate recorded by the receiver, in packets per second
    /// This isn't optional because the receiver sends this
    /// information to the sender in ACK packets.
    fn packet_arrival_rate(&self) -> i32;

    fn rtt(&self) -> Duration;

    fn estimated_bandwidth(&self) -> i32;


    /// Receiver doesn't have this info, so yields None
    fn packet_send_rate(&self) -> Option<i32>;

    /// The maximum packet size, in bytes
    fn max_packet_size(&self) -> i32;

    fn start_time(&self) -> Instant;

    /// Get the SRT timestamp, which is microseconds since `start_time`.
    fn get_timestamp(&self) -> i32 {
        (self.sock_start_time.elapsed().as_secs() * 1_000_000
            + (u64::from(self.sock_start_time.elapsed().subsec_nanos()) / 1_000)) as i32
    }
}
