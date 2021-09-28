use std::time::{Duration, Instant};

use crate::protocol::stats::*;

#[derive(Debug, Default)]
struct MessageStats {
    pub message_count: u64,
    pub packet_count: u64,
    pub bytes_total: u64,
}

impl Stats for MessageStats {
    type Measure = (u64, u64);

    fn add(&mut self, (packets, bytes): Self::Measure) {
        self.message_count += 1;
        self.packet_count += packets;
        self.bytes_total += bytes;
    }
}

impl StatsWindow<MessageStats> {
    pub fn mean_payload_size(&self) -> DataRate {
        if self.stats.packet_count > 0 {
            self.stats.bytes_total / self.stats.packet_count
        } else {
            0
        }
    }

    pub fn data_rate(&self) -> DataRate {
        if self.period.as_nanos() > 0 {
            (self.stats.bytes_total as f64 / self.period.as_secs_f64()) as u64
        } else {
            0
        }
    }
}

// rate in bytes per second
type DataRate = u64;
type Percent = u64;

// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-5.1.1
//
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
        rate: DataRate,     // m_llInputBW
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

#[derive(Debug)]
pub struct SenderCongestionControl {
    message_stats_window: OnlineWindowedStats<MessageStats>,
    message_stats: StatsWindow<MessageStats>,
    bandwidth_mode: LiveBandwidthMode,
    window_size: Option<usize>,
    current_data_rate: DataRate,
}

///
/// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-5.1.2
impl SenderCongestionControl {
    const GIGABIT: DataRate = 1_000_000_000 / 8;
    pub fn new(bandwidth_mode: LiveBandwidthMode, window_size: Option<usize>) -> Self {
        Self {
            message_stats_window: OnlineWindowedStats::new(Duration::from_secs(1)),
            message_stats: Default::default(),
            bandwidth_mode,
            window_size,
            current_data_rate: Self::GIGABIT,
        }
    }

    pub fn on_input(&mut self, now: Instant, packets: u64, data_length: u64) {
        let stats = self.message_stats_window.add(now, (packets, data_length));
        if let Some(stats) = stats {
            self.current_data_rate = self.updated_data_rate(stats.data_rate());
            self.message_stats = stats;
        }
    }

    // from https://github.com/Haivision/srt/blob/580d8992c20ba4ff48d58b29fddf5fd5e7037f9d/srtcore/congctl.cpp#L166-L166
    pub fn snd_period(&self) -> Duration {
        if self.current_data_rate > 0 {
            const UDP_HEADER_SIZE: usize = 28; // 20 bytes for IPv4 header, 8 bytes for UDP header
            const HEADER_SIZE: usize = 16;
            const SRT_DATA_HEADER_SIZE: usize = UDP_HEADER_SIZE + HEADER_SIZE;

            let mean_packet_size =
                self.message_stats.mean_payload_size() + SRT_DATA_HEADER_SIZE as u64;
            // multiply packet size to adjust data rate to microseconds (i.e. x 1,000,000)
            let period = mean_packet_size as u64 * 1_000_000 / self.current_data_rate as u64;

            if period > 0 {
                return Duration::from_micros(period);
            }
        }
        Duration::from_micros(1)
    }

    pub fn window_size(&self) -> u32 {
        // Up to SRT 1.0.6, this value was set at 1000 pkts, which may be insufficient
        // for satellite links with ~1000 msec RTT and high bit rate.
        self.window_size.unwrap_or(10_000) as u32
    }

    /// When an ACK packet is received
    pub fn on_ack(&mut self) {}

    // When a NAK packet is received
    // pub fn on_nak(&mut self, _largest_seq_in_ll: SeqNumber) {}

    /// On packet sent
    pub fn on_packet_sent(&mut self) {}

    fn updated_data_rate(&mut self, actual_data_rate: DataRate) -> DataRate {
        use LiveBandwidthMode::*;
        match self.bandwidth_mode {
            Input { rate, overhead } => rate * (100 + overhead) / 100,
            Set(max) => max,
            Unlimited => Self::GIGABIT,
            Estimated { overhead, .. } => actual_data_rate * (100 + overhead) / 100,
        }
    }
}

#[cfg(test)]
mod sender_congestion_control {
    use super::*;

    #[test]
    fn data_rate_unlimited() {
        let data_rate = LiveBandwidthMode::Unlimited;

        let ms = Duration::from_millis;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate, None);

        // initialize statistics
        control.on_input(start, 0, 0);

        for n in 1..1001 {
            control.on_input(start + ms(n), 2, 2_000);
        }

        assert_eq!(control.snd_period(), Duration::from_micros(8));
    }

    #[test]
    fn data_rate_fixed() {
        let fixed_rate = 1_000_000;
        let fixed_overhead = 100;
        let data_rate = LiveBandwidthMode::Input {
            rate: fixed_rate,
            overhead: fixed_overhead,
        };
        let expected_data_rate = (fixed_overhead + 100) * fixed_rate / 100;

        let mean_payload_size = 1_000_000;
        let packet_header_size = 44;
        let expected_mean_packet_size = mean_payload_size + packet_header_size;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate, None);

        // initialize statistics
        control.on_input(start, 0, 0);
        control.on_input(start, 1, mean_payload_size);
        control.on_input(start + micros(1_000_000), 0, 0);

        let expected_snd_period =
            (expected_mean_packet_size as u64 * 1_000_000) / expected_data_rate as u64;

        assert_eq!(control.snd_period(), micros(expected_snd_period));
    }

    #[test]
    fn data_rate_max() {
        let max_data_rate = 10_000_000;
        let data_rate = LiveBandwidthMode::Set(max_data_rate);
        let expected_data_rate = max_data_rate;

        let mean_payload_size = 1_000_000;
        let packet_header_size = 44;
        let expected_mean_packet_size = mean_payload_size + packet_header_size;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate, None);

        // initialize statistics
        control.on_input(start, 0, 0);
        control.on_input(start, 1, mean_payload_size);
        control.on_input(start + micros(1_000_000), 0, 0);

        let expected_snd_period =
            (expected_mean_packet_size as u64 * 1_000_000) / expected_data_rate as u64;

        assert_eq!(control.snd_period(), micros(expected_snd_period));
    }

    #[test]
    fn data_rate_auto() {
        let auto_overhead = 5;
        let data_rate = LiveBandwidthMode::Estimated {
            overhead: auto_overhead,
        };
        let expected_data_rate = ((100 + auto_overhead) * 1_000_000) / 100;

        let mean_payload_size = 1_000_000;
        let packet_header_size = 44;
        let expected_mean_packet_size = mean_payload_size + packet_header_size;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate, None);

        // initialize statistics
        control.on_input(start, 0, 0);
        control.on_input(start, 1, mean_payload_size);
        control.on_input(start + micros(1_000_000), 0, 0);

        let expected_snd_period =
            (expected_mean_packet_size as u64 * 1_000_000) / expected_data_rate as u64;

        assert_eq!(control.snd_period(), micros(expected_snd_period));
    }
}
