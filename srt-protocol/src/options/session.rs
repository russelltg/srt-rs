use std::time::Duration;

pub struct SessionOptions {
    /// SRTO_PEERIDLETIMEO - default 5000ms
    /// The maximum time in [ms] to wait until another packet is received from a peer since the last
    /// such packet reception. If this time is passed, the connection is considered broken on
    /// timeout.
    peer_idle_timeout: Duration,

    /// SRTO_MINVERSION
    /// The minimum SRT version that is required from the peer. A connection to a peer that does not satisfy the minimum version requirement will be rejected. See SRTO_VERSION for the version format.
    ///
    /// The default value is 0x010000 (SRT v1.0.0).

    /// SRTO_MSS
    /// Maximum Segment Size. Used for buffer allocation and rate calculation using packet counter
    /// assuming fully filled packets. Each party can set its own MSS value independently. During a
    /// handshake the parties exchange MSS values, and the lowest is used.
    ///
    /// Generally on the internet MSS is 1500 by default. This is the maximum size of a UDP packet and
    /// can be only decreased, unless you have some unusual dedicated network settings. MSS is not to be
    /// confused with the size of the UDP payload or SRT payload - this size is the size of the IP
    /// packet, including the UDP and SRT headers
    ///
    /// THe value of SRTO_MSS must not exceed SRTO_UDP_SNDBUF or SRTO_UDP_RCVBUF.
    max_segment_size: usize,

    // TODO: connections are always duplex, so why do we need more than one configured value?
    /// SRTO_LATENCY - default 120ms
    /// This option sets both SRTO_RCVLATENCY and SRTO_PEERLATENCY to the same value specified.
    ///
    /// Prior to SRT version 1.3.0 SRTO_LATENCY was the only option to set the latency. However it is
    /// effectively equivalent to setting SRTO_PEERLATENCY in the sending direction (see
    /// SRTO_SENDER), and SRTO_RCVLATENCY in the receiving direction. SRT version 1.3.0 and higher
    /// support bidirectional transmission, so that each side can be sender and receiver at the same
    /// time, and SRTO_SENDER became redundant.
    latency: Duration,

    statistics_interval: Duration,
}
