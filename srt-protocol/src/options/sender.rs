use std::{default::Default, time::Duration};

pub struct SenderOptions {
    // OptName	Since	Restrict	Type	Units	Default	Range	Dir	Entity
    // SRTO_PEERLATENCY	1.3.0	pre	int32_t	ms	0	0..	RW	GSD
    /// SRTO_PEERLATENCY
    /// The latency value (as described in SRTO_RCVLATENCY) provided by the sender side as a minimum
    /// value for the receiver.
    ///
    /// Reading the value of the option on an unconnected socket reports the configured value.
    /// Reading the value on a connected socket reports the effective receiver buffering latency of
    /// the peer.
    ///
    /// The SRTO_PEERLATENCY option in versions prior to 1.3.0 is only available as SRTO_LATENCY.
    ///
    /// See also SRTO_LATENCY.
    pub peer_latency: Duration,

    // OptName	Since	Restrict	Type	Units	Default	Range	Dir	Entity
    // SRTO_SNDDROPDELAY	1.3.2	post	int32_t	ms	*	-1..	W	GSD+
    /// SRTO_SNDDROPDELAY
    /// Sets an extra delay before TLPKTDROP is triggered on the data sender. This delay is added to the default drop delay time interval value. Keep in mind that the longer the delay, the more probable it becomes that packets would be retransmitted uselessly because they will be dropped by the receiver anyway.
    ///
    /// TLPKTDROP discards packets reported as lost if it is already too late to send them (the receiver would discard them even if received). The delay before the TLPKTDROP mechanism is triggered consists of the SRT latency (SRTO_PEERLATENCY), plus SRTO_SNDDROPDELAY, plus 2 * interval between sending ACKs (where the default interval between sending ACKs is 10 milliseconds). The minimum delay is 1000 + 2 * interval between sending ACKs milliseconds.
    ///
    /// Special value -1: Do not drop packets on the sender at all (retransmit them always when requested).
    ///
    /// Default: 0 in Live mode, -1 in File mode.
    pub drop_delay: Duration,

    /// SRTO_SNDBUF
    /// Sender Buffer Size. See SRTO_RCVBUF for more information.
    pub buffer_size: usize,

    // SRTO_OHEADBW - see LiveBandwidthMode
    // SRTO_MAXBW - see LiveBandwidthMode
    // SRTO_INPUTBW - see LiveBandwidthMode
    // SRTO_MININPUTBW - see LiveBandwidthMode
    pub bandwidth_mode: LiveBandwidthMode,

    /// SRTO_FC - Flow Control Window Size - unit: packets, default 25600, range: 32..
    /// Flow Control limits the maximum number of packets "in flight" - payload (data) packets that
    /// were sent but reception is not yet acknowledged with an ACK control packet. It also includes
    /// data packets already received, but that can't be acknowledged due to loss of preceding data
    /// packet(s). In other words, if a data packet with sequence number A was lost, then
    /// acknowledgement of the following SRTO_FC packets is blocked until packet A is either
    /// successfully retransmitted or dropped by the Too-Late Packet Drop mechanism. Thus the sender
    /// will have SRTO_FC packets in flight, and will not be allowed to send further data packets.
    /// Therefore, when establishing the value of SRTO_FC, it is recommend taking into consideration
    /// possible delays due to packet loss and retransmission.
    ///
    /// There is a restriction that the receiver buffer size (SRTO_RCVBUF) must not be greater than
    /// SRTO_FC (#700). Therefore, it is recommended to set the value of SRTO_FC first, and then the
    /// value of SRTO_RCVBUF.
    ///
    /// The default flow control window size is 25600 packets. It is approximately:
    /// - 270 Mbits of payload in the default live streaming configuration with an SRT payload size of 1316 bytes;
    /// - 300 Mbits of payload with an SRT payload size of 1456 bytes.
    ///
    /// The minimum number of packets in flight should be (assuming max payload size):
    /// `FCmin = bps / 8 × RTTsec / (MSS - 44)`, where:
    /// - bps - is the payload bitrate of the stream in bits per second;
    /// - RTTsec - RTT of the network connection in seconds;
    /// - MSS - Maximum segment size (aka MTU), see SRTO_MSS;
    /// - 44 - size of headers (20 bytes IPv4 + 8 bytes of UDP + 16 bytes of SRT packet header).
    /// - To avoid blocking the sending of further packets in case of packet loss, the recommended flow control window is
    /// - FC = bps / 8 × (RTTsec + latency_sec) / (MSS - 44), where latency_sec is the receiver buffering delay (SRTO_RCVLATENCY) in seconds.
    pub flow_control_window_size: usize,

    /// SRTO_PAYLOADSIZE
    /// Sets the maximum declared size of a single call to sending function in Live mode. When set to 0,
    /// there's no limit for a single sending call.
    ///
    /// For Live mode: Default value is 1316, but can be increased up to 1456. Note that with the
    /// SRTO_PACKETFILTER option additional header space is usually required, which decreases the
    /// maximum possible value for SRTO_PAYLOADSIZE.
    pub max_payload_size: usize,

    /// SRTO_RETRANSMITALGO - prioritize this
    ///
    /// An SRT sender option to choose between two retransmission algorithms:
    ///
    /// 0 - an intensive retransmission algorithm (default until SRT v1.4.4), and
    /// 1 - a new efficient retransmission algorithm (introduced in SRT v1.4.2; default since
    /// SRT v1.4.4).
    ///
    /// The intensive retransmission algorithm causes the SRT sender to schedule a packet for
    /// retransmission each time it receives a negative acknowledgement (NAK). On a network
    /// characterized by low packet loss levels and link capacity high enough to accommodate extra
    /// retransmission overhead, this algorithm increases the chances of recovering from packet loss
    /// with a minimum delay, and may better suit end-to-end latency constraints.
    ///
    /// The new efficient algorithm optimizes the bandwidth usage by producing fewer retransmissions per
    /// lost packet. It takes SRT statistics into account to determine if a retransmitted packet is
    /// still in flight and could reach the receiver in time, so that some of the NAK reports are
    /// ignored by the sender. This algorithm better fits general use cases, as well as cases where
    /// channel bandwidth is limited.
    ///
    /// NOTE: This option is effective only on the sending side. It influences the decision as to
    /// whether a particular reported lost packet should be retransmitted at a certain time or not.
    ///
    /// NOTE: The efficient retransmission algorithm can only be used when a receiver sends Periodic NAK
    /// reports. See SRTO_NAKREPORT.
    pub intensive_retransmission: bool,
}

impl Default for SenderOptions {
    fn default() -> Self {
        Self {
            peer_latency: Duration::from_millis(120),
            drop_delay: Duration::ZERO,
            buffer_size: 46592,
            bandwidth_mode: Default::default(),
            flow_control_window_size: 25600,
            max_payload_size: 1316,
            intensive_retransmission: false,
        }
    }
}

// rate in bytes per second
pub type DataRate = u64;
pub type Percent = u64;

/// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-5.1.1
///
/// Note that Maximum Bandwidth, Input Rate, and Input Rate Estimate are bytes per second
/// and Overhead is a percentage.
#[derive(Debug, Clone)]
pub enum LiveBandwidthMode {
    /// Set the maximum bandwidth explicitly.
    ///
    /// The recommended default value is 1 Gbps. The default value is set only for live streaming.
    ///
    /// Note that this static setting is not well-suited to a variable input, like when you change the bitrate on an encoder.
    /// Each time the input bitrate is configured on the encoder, this value should also be reconfigured.
    Set(DataRate), // m_llMaxBW != 0

    /// Set the SRT send input rate and overhead.
    /// In this mode, SRT calculates the maximum bandwidth as follows:
    ///
    ///   Maximum Bandwidth = Input Rate * (1 + Overhead / 100)
    ///
    /// Note that Input mode reduces to the Set mode and the same restrictions apply.
    Input {
        // m_llInputBW != 0
        rate: DataRate,    // m_llInputBW
        overhead: Percent, // m_iOverheadBW
    },

    /// Measure the SRT send input rate internally and set the Overhead.
    ///
    /// In this mode, SRT adjusts the value of maximum bandwidth each time it gets the updated
    /// Input Rate Estimate of the Input Rate:
    ///
    ///   Maximum Bandwidth = Input Rate Estimate * (1 + Overhead / 100)
    ///
    /// Estimated mode is recommended for setting the Maximum Bandwidth as it follows the
    /// fluctuations in SRT send Input Rate. However, there are certain considerations that
    /// should be taken into account.
    ///
    ///
    /// In Estimated mode, SRT takes as an initial Expected Input Rate. This should match the
    /// configured output bitrate rate of an encoder (in terms of bitrate for the packets including
    /// audio and overhead). But it is normal for an encoder to occasionally overshoot. At a low
    /// bitrate, sometimes an encoder can be too optimistic and will output more bits than expected.
    /// Under these conditions, SRT packets would not go out fast enough because the configured
    /// bandwidth limitation would be too low. This is mitigated by calculating the bitrate
    /// internally.
    ///
    /// SRT examines the packets being submitted and calculates an Input Rate Estimate as a moving
    /// average. However, this introduces a bit of a delay based on the content. It also means that
    /// if an encoder encounters black screens or still frames, this would dramatically lower the
    /// bitrate being measured, which would in turn reduce the SRT output rate. And then, when the
    /// video picks up again, the input rate rises sharply. SRT would not start up again fast
    /// enough on output because of the time it takes to measure the speed. Packets might be
    /// accumulated in the SRT send buffer, and delayed as a result, causing them to arrive too late
    /// at the decoder, and possible drops by the receiver.
    Estimated {
        // expected: DataRate,     // m_llInputBW
        // m_llMaxBW == 0 && m_llInputBW == 0
        overhead: Percent, // m_iOverheadBW
    },
    Unlimited,
}

impl Default for LiveBandwidthMode {
    fn default() -> Self {
        LiveBandwidthMode::Unlimited
    }
}
