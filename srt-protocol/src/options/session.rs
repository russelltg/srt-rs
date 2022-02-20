use std::time::Duration;

use super::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Session {
    /// SRTO_PEERIDLETIMEO
    /// The maximum time to wait until another packet is received from a peer since the last
    /// such packet reception. If this time is passed, the connection is considered broken on
    /// timeout.
    ///
    ///  The default value is 5000ms
    pub peer_idle_timeout: Duration,

    /// SRTO_MSS
    /// Maximum Segment Size. Used for buffer allocation and rate calculation using packet counter
    /// assuming fully filled packets. Each party can set its own MSS value independently. During a
    /// handshake the parties exchange MSS values, and the lowest is used.
    ///
    /// Generally on the internet MSS is 1500 by default. This is the maximum size of a UDP packet
    /// and can be only decreased, unless you have some unusual dedicated network settings. MSS is
    /// not to be confused with the size of the UDP payload or SRT payload - this size is the size
    /// of the IP packet, including the UDP and SRT headers
    ///
    /// THe value of SRTO_MSS must not exceed SRTO_UDP_SNDBUF or SRTO_UDP_RCVBUF.
    pub max_segment_size: PacketSize,

    pub statistics_interval: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            peer_idle_timeout: Duration::from_secs(5),
            max_segment_size: PacketSize(1500),
            statistics_interval: Duration::from_secs(1),
        }
    }
}

impl Validation for Session {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        use OptionsError::*;
        if self.max_segment_size > PacketSize(1500) {
            Err(MaxSegmentSizeOutOfRange(self.max_segment_size))
        } else if self.statistics_interval < Duration::from_millis(200) {
            Err(StatisticsIntervalOutOfRange(self.statistics_interval))
        } else {
            Ok(())
        }
    }
}
