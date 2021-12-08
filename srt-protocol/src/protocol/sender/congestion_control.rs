use std::time::{Duration, Instant};

use crate::options::{ByteCount, DataRate, LiveBandwidthMode, PacketCount, PacketRate};

#[derive(Debug, Default)]
pub struct RateEstimate {
    pub mean: u64,
    pub variance: u64,
}

#[derive(Debug, Default)]
pub struct RateEstimation {
    total: i128,
    last: i128,
    mean: i128,
    variance: i128,
}

impl RateEstimation {
    pub fn increment(&mut self, count: u64) {
        self.total += count as i128;
    }

    pub fn calculate(&mut self, time: Duration) -> RateEstimate {
        let count = self.total - self.last;
        let time = time.as_micros() as i128;
        if time > 0 {
            let rate = count * 1_000_000 / time;
            if self.mean == 0 && self.variance == 0 {
                self.mean = rate;
            } else {
                // favor speeding up over slowing down
                self.mean = if rate > self.mean {
                    (self.mean + rate) / 2
                } else {
                    (self.mean * 7 + rate) / 8
                };
                let diff = (self.mean - rate).abs();
                self.variance = (self.variance * 3 + diff) / 4;
            }
            self.last = self.total;
        }
        RateEstimate {
            mean: self.mean as u64,
            variance: self.variance as u64,
        }
    }
}

#[derive(Debug, Default)]
pub struct InputRateEstimate {
    pub messages: RateEstimate,
    pub packets: RateEstimate,
    pub bytes: RateEstimate,
}

#[derive(Debug, Default)]
pub struct InputRateEstimation {
    pub messages: RateEstimation,
    pub packets: RateEstimation,
    pub bytes: RateEstimation,
}

impl InputRateEstimation {
    fn add(&mut self, (packets, bytes): (PacketCount, ByteCount)) {
        self.messages.increment(1);
        self.packets.increment(packets.into());
        self.bytes.increment(bytes.into());
    }

    pub fn calculate(&mut self, elapsed: Duration) -> InputRateEstimate {
        InputRateEstimate {
            messages: self.messages.calculate(elapsed),
            packets: self.packets.calculate(elapsed),
            bytes: self.bytes.calculate(elapsed),
        }
    }
}

#[derive(Debug)]
pub struct SenderCongestionControl {
    next: Option<Instant>,
    estimation: InputRateEstimation,
    bandwidth_mode: LiveBandwidthMode,
}

// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-5.1.2
impl SenderCongestionControl {
    const GIGABIT: u64 = 1_000_000_000 / 8;

    pub fn new(bandwidth_mode: LiveBandwidthMode) -> Self {
        Self {
            next: None,
            estimation: InputRateEstimation::default(),
            bandwidth_mode,
        }
    }

    pub fn on_input(
        &mut self,
        now: Instant,
        packets: PacketCount,
        bytes: ByteCount,
    ) -> Option<Duration> {
        const PERIOD: Duration = Duration::from_millis(100);
        let result = match self.next.as_mut() {
            None => {
                self.next = Some(now + PERIOD);
                None
            }
            Some(next) if now < *next => None,
            Some(next) => {
                let overflow = now - *next;
                let overflow_periods = overflow.as_millis() / PERIOD.as_millis();
                let elapsed_periods = 1 + overflow_periods as u32;
                let elapsed = elapsed_periods * PERIOD;
                *next += elapsed;

                let estimate = self.estimation.calculate(elapsed);
                let data_rate = estimate.bytes.mean;
                let packet_rate = estimate.packets.mean;

                Some(self.calculate_snd_period(packet_rate.into(), data_rate.into()))
            }
        };

        self.estimation.add((packets, bytes));

        result
    }

    fn calculate_max_data_rate(&self, actual_data_rate: DataRate) -> DataRate {
        use LiveBandwidthMode::*;
        match self.bandwidth_mode {
            Input { rate, overhead } => rate * (overhead + 100),
            Set(max) => max,
            Unlimited => Self::GIGABIT.into(),
            Estimated { overhead, .. } => actual_data_rate * (overhead + 100),
        }
    }

    // from https://github.com/Haivision/srt/blob/580d8992c20ba4ff48d58b29fddf5fd5e7037f9d/srtcore/congctl.cpp#L166-L166
    fn calculate_snd_period(&self, packet_rate: PacketRate, data_rate: DataRate) -> Duration {
        let max_data_rate = self.calculate_max_data_rate(data_rate);
        if packet_rate > 0.into() && max_data_rate > 0.into() {
            if let Some(period) = max_data_rate.period_for(data_rate / packet_rate) {
                return period;
            }
        }
        Duration::from_micros(1)
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
        let mut control = SenderCongestionControl::new(data_rate);

        // initialize statistics
        control.on_input(start, PacketCount(0), ByteCount(0));

        for n in 1..100 {
            control.on_input(start + ms(n), PacketCount(2), ByteCount(2_000));
        }
        let snd_period = control.on_input(start + ms(1001), PacketCount(0), ByteCount(0));

        assert_eq!(snd_period, Some(Duration::from_micros(8)));
    }

    #[test]
    fn data_rate_fixed() {
        let fixed_rate = 1_000_000;
        let fixed_overhead = 100;
        let data_rate = LiveBandwidthMode::Input {
            rate: fixed_rate.into(),
            overhead: fixed_overhead.into(),
        };
        let expected_data_rate = (fixed_overhead + 100) * fixed_rate / 100;
        let mean_packet_size = 100_000;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate);

        // initialize statistics
        assert_eq!(control.on_input(start, PacketCount(0), ByteCount(0)), None);
        assert_eq!(
            control.on_input(start, PacketCount(1), ByteCount(mean_packet_size)),
            None
        );
        let snd_period = control.on_input(start + micros(100_000), PacketCount(0), ByteCount(0));

        let expected_snd_period = mean_packet_size * 10 * 100_000 / expected_data_rate;

        assert_eq!(snd_period, Some(micros(expected_snd_period)));
    }

    #[test]
    fn data_rate_max() {
        let max_data_rate = 10_000_000;
        let data_rate = LiveBandwidthMode::Set(max_data_rate.into());
        let expected_data_rate = max_data_rate;
        let mean_packet_size = 100_000;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate);

        // initialize statistics
        assert_eq!(control.on_input(start, PacketCount(0), ByteCount(0)), None);
        assert_eq!(
            control.on_input(start, PacketCount(1), ByteCount(mean_packet_size)),
            None
        );
        let snd_period = control.on_input(start + micros(100_000), PacketCount(0), ByteCount(0));

        let expected_snd_period = (mean_packet_size * 10 * 100_000) / expected_data_rate as u64;

        assert_eq!(snd_period, Some(micros(expected_snd_period)));
    }

    #[test]
    fn data_rate_auto() {
        let auto_overhead = 5;
        let data_rate = LiveBandwidthMode::Estimated {
            overhead: auto_overhead.into(),
        };
        let expected_data_rate = ((100 + auto_overhead) * 10 * 100_000) / 100;
        let mean_packet_size = 100_000;

        let micros = Duration::from_micros;
        let start = Instant::now();
        let mut control = SenderCongestionControl::new(data_rate);

        // initialize statistics
        assert_eq!(
            control.on_input(start, PacketCount(0), ByteCount(0)),
            None
        );
        assert_eq!(
            control.on_input(start, PacketCount(1), ByteCount(mean_packet_size)),
            None
        );
        let snd_period = control.on_input(start + micros(100_000), PacketCount(0), ByteCount(0));

        let expected_snd_period = mean_packet_size * 10 * 100_000 / expected_data_rate;

        assert_eq!(snd_period, Some(micros(expected_snd_period)));
    }
}
