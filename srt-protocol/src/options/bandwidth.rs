// rate in bytes per second
use super::*;

/// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-5.1.1
///
/// Note that Maximum Bandwidth, Input Rate, and Input Rate Estimate are bytes per second
/// and Overhead is a percentage.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LiveBandwidthMode {
    /// Set the maximum bandwidth explicitly.
    ///
    /// The recommended default value is 1 Gbps. The default value is set only for live streaming.
    ///
    /// Note that this static setting is not well-suited to a variable input, like when you change
    /// the bitrate on an encoder. Each time the input bitrate is configured on the encoder, this
    /// value should also be reconfigured.
    Max(DataRate), // m_llMaxBW != 0

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
        // m_llMaxBW == 0 && m_llInputBW == 0
        overhead: Percent,  // m_iOverheadBW
        expected: DataRate, // SRTO_MININPUTBW
    },
    Unlimited,
}

impl Default for LiveBandwidthMode {
    fn default() -> Self {
        LiveBandwidthMode::Unlimited
    }
}
