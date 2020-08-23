use std::cmp::{max, min};
use std::time::{Duration, Instant};

use stats::OnlineStats;

use crate::protocol::time::{TimeBase, TimeSpan, TimeStamp, Timer};

pub(crate) struct SynchronizedRemoteClock {
    tolerance: Duration,
    time_base: TimeBase,
    stats: Option<OnlineStats>,
}

impl SynchronizedRemoteClock {
    const MAX_SAMPLES: usize = 1_000;
    const DRIFT_TOLERANCE: Duration = Duration::from_millis(5);

    pub fn new(now: Instant) -> Self {
        Self {
            // TODO: Drift deviation tolerance should be parameterized.
            //       It wasn't in the reference implementation, but I added it because the reference
            //       implementation is susceptible to invalid clock adjustments during periods of
            //       acute network latency
            tolerance: Self::DRIFT_TOLERANCE,
            time_base: TimeBase::new(now),
            stats: None,
        }
    }

    pub fn synchronize(&mut self, now: Instant, ts: TimeStamp) {
        let drift = self.time_base.timestamp_from(now) - ts;
        match &mut self.stats {
            None => {
                self.time_base.adjust(now, drift);
            }
            Some(stats) => {
                stats.add(drift.as_micros());

                if stats.len() < Self::MAX_SAMPLES {
                    return;
                }

                if stats.stddev() < self.tolerance.as_micros() as f64 {
                    self.time_base
                        .adjust(now,TimeSpan::from_micros(stats.mean() as i32));
                }
            }
        }
        self.stats = Some(OnlineStats::new());
    }

    pub fn instant_from(&self, ts: TimeStamp) -> Instant {
        self.time_base.instant_from(ts)
    }

    pub fn origin_time(&self) -> Instant {
        self.time_base.origin_time()
    }
}

#[cfg(test)]
mod synchronized_remote_clock {
    use std::{cmp::Ordering, time::Duration};

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn synchronize(drift_ts in 1u64..5_000_000) {
            const MAX_SAMPLES: i32 = 1000;

            let drift = Duration::from_micros(drift_ts);
            let start = Instant::now();
            let start_ts = TimeStamp::from_u32(100_000_000);

            let mut clock = SynchronizedRemoteClock::new(start);

            clock.synchronize(start, start_ts);
            let instant = clock.instant_from(start_ts);

            prop_assert_eq!(instant, start, "the clock should be adjusted on the first sample");

            for tick_ts in 1..1002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                clock.synchronize(now, now_ts);
                let instant = clock.instant_from(now_ts);

                match tick_ts.cmp(&MAX_SAMPLES) {
                    Ordering::Less => assert_eq!(instant, start + tick, "the clock should not be adjusted until {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                    Ordering::Equal => assert_eq!(instant, now, "the clock should be adjusted after {} samples", MAX_SAMPLES),
                    Ordering::Greater => assert_eq!(instant, now, "the clock should not be adjusted until the next {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                }
            }

            // simulate drift variance outside tolerance (+/- 5ms)
            for tick_ts in 1002..2002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                clock.synchronize(now, now_ts - TimeSpan::from_micros((tick_ts % 2) * 11000)); // constant 5ms drift variance
                let instant = clock.instant_from(now_ts);

                prop_assert_eq!(instant, now, "the clock should not be adjusted: tick_ts = {}", tick_ts);
            }
        }
    }
}

pub(crate) struct RTT {
    mean: TimeSpan,
    variance: TimeSpan,
}

impl RTT {
    pub fn new() -> Self {
        Self {
            mean: TimeSpan::from_micros(10_000),
            variance: TimeSpan::from_micros(1_000),
        }
    }

    pub fn update(&mut self, rtt: TimeSpan) {
        self.mean = TimeSpan::from_micros(
            ((self.mean.as_micros() as i64 * 7 + rtt.as_micros() as i64) / 8) as i32,
        );
        self.variance = TimeSpan::from_micros(
            ((self.variance.as_micros() as i64 * 3
                + (self.mean.as_micros() as i64 - rtt.as_micros() as i64).abs() as i64)
                / 4) as i32,
        );
    }

    pub fn mean(&self) -> TimeSpan {
        self.mean
    }

    pub fn variance(&self) -> TimeSpan {
        self.variance
    }

    pub fn mean_as_duration(&self) -> Duration {
        Duration::from_micros(self.mean.as_micros() as u64)
    }

    pub fn variance_as_duration(&self) -> Duration {
        Duration::from_micros(self.variance.as_micros() as u64)
    }
}

pub(crate) struct ReceiveTimers {
    pub(crate) ack: Timer,
    pub(crate) nak: Timer,
}

impl ReceiveTimers {
    const SYN: Duration = Duration::from_millis(10);

    pub fn new(now: Instant) -> ReceiveTimers {
        let (ack, nak) = Self::calculate_periods(&RTT::new());
        ReceiveTimers {
            ack: Timer::new(ack, now),
            nak: Timer::new(nak, now),
        }
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        max(now, min(self.nak.next_instant(), self.ack.next_instant()))
    }

    pub fn check_ack(&mut self, now: Instant) -> Option<Instant> {
        self.ack.check_expired(now)
    }

    pub fn check_nak(&mut self, now: Instant) -> Option<Instant> {
        self.nak.check_expired(now)
    }

    pub fn update_rtt(&mut self, rtt: &RTT) {
        let (ack, nak) = Self::calculate_periods(rtt);
        self.ack.set_period(ack);
        self.nak.set_period(nak);
    }

    fn calculate_periods(rtt: &RTT) -> (Duration, Duration) {
        let rtt_period = 4 * rtt.mean_as_duration() + rtt.variance_as_duration() + Self::SYN;

        let ack_period = rtt_period;

        let nak_report_period_accelerator: u32 = 2;
        let nak_period = nak_report_period_accelerator * rtt_period;

        (ack_period, nak_period)
    }
}

#[cfg(test)]
mod receive_timers {
    use super::*;
    use proptest::prelude::*;

    fn diff(a: Instant, b: Instant) -> Duration {
        if a > b {
            a - b
        } else {
            b - a
        }
    }

    #[test]
    fn next_timer() {
        let ms = Duration::from_millis;
        let rtt_mean = ms(10);
        let rtt_variance = ms(1);
        let syn = ms(10);
        let start = Instant::now();
        let mut timers = ReceiveTimers::new(start);

        // next timer should be ack
        // 4 * RTT + RTTVar + SYN
        let ack = 4 * rtt_mean + rtt_variance + syn;
        let now = start;
        let actual_timer = timers.next_timer(now);
        assert_eq!(diff(actual_timer, now), ack);

        // only ack timer should fire
        assert!(timers.ack.check_expired(actual_timer).is_some());
        assert!(timers.nak.check_expired(actual_timer).is_none());

        // next timer should be nak
        // NAK accelerator * 4 * RTT + RTTVar + SYN
        let nak = 2 * (4 * rtt_mean + rtt_variance + syn);
        let now = actual_timer;
        let actual_timer = timers.next_timer(now);
        assert_eq!(diff(actual_timer, start), nak);

        // both ack and nak should fire because their periods overlap
        assert!(timers.ack.check_expired(actual_timer).is_some());
        assert!(timers.nak.check_expired(actual_timer).is_some());

        // exp will have a lower bound period of 500ms
        let exp = ms(500);
        let now = start + exp;

        // push time forward for ack and nak first
        assert!(timers.ack.check_expired(now).is_some());
        assert!(timers.nak.check_expired(now).is_some());
    }

    proptest! {
        #[test]
        fn update_rtt(simulated_rtt in 45_000i32..) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = RTT::new();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // above lower bound of exp
            prop_assume!(4 * rtt_mean + rtt_variance + syn > ms(500));

            let start = Instant::now();
            let mut timers = ReceiveTimers::new(start);

            timers.update_rtt(&rtt);

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.ack.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);

            // NAK accelerator * 4 * RTT + RTTVar + SYN
            assert_eq!(timers.nak.next_instant() - start, 2 * (4 * rtt_mean + rtt_variance + syn));
        }

        #[test]
        fn update_rtt_exp_lower_bound(simulated_rtt in 0i32..50_000) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = RTT::new();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // below lower bound of exp
            prop_assume!(4 * rtt_mean + rtt_variance + syn <= ms(500));

            let start = Instant::now();
            let mut timers = ReceiveTimers::new(start);

            timers.update_rtt(&rtt);

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.ack.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);

            // NAK accelerator * 4 * RTT + RTTVar + SYN
            assert_eq!(timers.nak.next_instant() - start, 2 * (4 * rtt_mean + rtt_variance + syn));
        }
    }
}
