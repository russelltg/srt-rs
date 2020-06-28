use std::time::{Duration, Instant};

use crate::protocol::stats::*;
use crate::SeqNumber;

struct MessageStats {
    pub message_count: usize,
    pub packet_count: usize,
    pub bytes_total: usize,
}

impl Default for MessageStats {
    fn default() -> Self {
        Self {
            message_count: 0,
            packet_count: 0,
            bytes_total: 0,
        }
    }
}

impl Stats for MessageStats {
    type Measure = (usize, usize);

    fn add(&mut self, (packets, bytes): Self::Measure) {
        self.message_count += 1;
        self.packet_count += packets;
        self.bytes_total += bytes;
    }
}

impl StatsWindow<MessageStats> {
    pub fn mean_payload_size(&self) -> usize {
        if self.stats.packet_count > 0 {
            self.stats.bytes_total / self.stats.packet_count
        } else {
            0
        }
    }

    pub fn data_rate(&self) -> usize {
        if self.period.as_nanos() > 0 {
            (self.stats.bytes_total as f64 / self.period.as_secs_f64()) as usize
        } else {
            0
        }
    }
}

// rate in bytes per second
type DataRate = usize;

// TODO: move data rate algorithm configuration to a public protocol configuration module
//       for now, just ignore that it's never used
#[allow(dead_code)]
pub(crate) enum LiveDataRate {
    Fixed {
        // m_llInputBW != 0
        rate: DataRate,     // m_llInputBW
        overhead: DataRate, // m_iOverheadBW
    },
    Max(DataRate), // m_llMaxBW != 0
    Auto {
        // m_llMaxBW == 0 && m_llInputBW == 0
        overhead: DataRate, // m_iOverheadBW
    },
    Unlimited,
}

pub(crate) struct SenderCongestionControl {
    message_stats_window: OnlineWindowedStats<MessageStats>,
    message_stats: StatsWindow<MessageStats>,
    live_data_rate: LiveDataRate,
    window_size: Option<usize>,
    current_data_rate: DataRate,
}

impl SenderCongestionControl {
    const GIGABIT: DataRate = 1_000_000_000 / 8;
    pub fn new(live_data_rate: LiveDataRate, window_size: Option<usize>) -> Self {
        Self {
            message_stats_window: OnlineWindowedStats::new(Duration::from_secs(1)),
            message_stats: Default::default(),
            live_data_rate,
            window_size,
            current_data_rate: Self::GIGABIT,
        }
    }

    pub fn on_input(&mut self, now: Instant, packets: usize, data_length: usize) {
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

            let mean_packet_size = self.message_stats.mean_payload_size() + SRT_DATA_HEADER_SIZE;
            // multiply packet size to adjust data rate to microseconds (i.e. x 1,000,000)
            let period = mean_packet_size * 1_000_000 / self.current_data_rate;

            if period > 0 {
                return Duration::from_micros(period as u64);
            }
        }
        Duration::from_micros(1)
    }

    pub fn window_size(&self) -> u32 {
        // Up to SRT 1.0.6, this value was set at 1000 pkts, which may be insufficient
        // for satellite links with ~1000 msec RTT and high bit rate.
        self.window_size.unwrap_or(1000) as u32
    }

    /// When an ACK packet is received
    pub fn on_ack(&mut self) {}

    /// When a NAK packet is received
    pub fn on_nak(&mut self, _largest_seq_in_ll: SeqNumber) {}

    /// On packet sent
    pub fn on_packet_sent(&mut self) {}

    fn updated_data_rate(&mut self, actual_data_rate: DataRate) -> DataRate {
        use LiveDataRate::*;
        match self.live_data_rate {
            Fixed { rate, overhead } => rate * (100 + overhead) / 100,
            Max(max) => max,
            Unlimited => Self::GIGABIT,
            Auto { overhead } => actual_data_rate * (100 + overhead) / 100,
        }
    }
}

#[cfg(test)]
mod sender_congestion_control {
    use super::*;

    #[test]
    fn data_rate_unlimited() {
        let data_rate = LiveDataRate::Unlimited;

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
        let data_rate = LiveDataRate::Fixed {
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

        let expected_snd_period = (expected_mean_packet_size * 1_000_000) / expected_data_rate;

        assert_eq!(control.snd_period(), micros(expected_snd_period as u64));
    }

    #[test]
    fn data_rate_max() {
        let max_data_rate = 10_000_000;
        let data_rate = LiveDataRate::Max(max_data_rate);
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

        let expected_snd_period = (expected_mean_packet_size * 1_000_000) / expected_data_rate;

        assert_eq!(control.snd_period(), micros(expected_snd_period as u64));
    }

    #[test]
    fn data_rate_auto() {
        let auto_overhead = 5;
        let data_rate = LiveDataRate::Auto {
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

        let expected_snd_period = (expected_mean_packet_size * 1_000_000) / expected_data_rate;

        assert_eq!(control.snd_period(), micros(expected_snd_period as u64));
    }
}
