use std::time::Instant;

use stats::OnlineStats;

use crate::{
    packet::{TimeSpan, TimeStamp},
    protocol::time::TimeBase,
};

#[derive(Debug)]
pub struct SynchronizedRemoteClock {
    drift_deviation_tolerance: TimeSpan,
    time_base: TimeBase,
    last_monotonic_instant: Option<Instant>,
    stats: Option<OnlineStats>,
    adjustments: u64,
    drift: (TimeSpan, TimeSpan),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClockAdjustment {
    mean: TimeSpan,
    stddev: TimeSpan,
}

impl SynchronizedRemoteClock {
    const MAX_SAMPLES: usize = 1_000;
    const DRIFT_DEVIATION_TOLERANCE: TimeSpan = TimeSpan::from_millis(5);

    pub fn new(now: Instant) -> Self {
        Self {
            // TODO: Drift deviation tolerance should be parameterized.
            //       It wasn't in the reference implementation, but I added it because the reference
            //       implementation is susceptible to invalid clock adjustments during periods of
            //       acute network latency
            drift_deviation_tolerance: Self::DRIFT_DEVIATION_TOLERANCE,
            time_base: TimeBase::new(now),
            last_monotonic_instant: None,
            adjustments: 0,
            drift: (TimeSpan::ZERO, TimeSpan::ZERO),
            stats: None,
        }
    }

    pub fn synchronize(&mut self, now: Instant, ts: TimeStamp) -> Option<ClockAdjustment> {
        let drift = self.time_base.timestamp_from(now) - ts;
        match &mut self.stats {
            None => {
                self.time_base.adjust(now, drift);
                self.stats = Some(OnlineStats::new());
                None
            }
            Some(stats) => {
                stats.add(drift.as_micros());
                if stats.len() < Self::MAX_SAMPLES {
                    return None;
                }

                let stddev = TimeSpan::from_micros(stats.stddev() as i32);
                let mean = TimeSpan::from_micros(stats.mean() as i32);

                self.stats = Some(OnlineStats::new());
                if stddev > self.drift_deviation_tolerance {
                    return None;
                }

                self.time_base.adjust(now, mean);
                Some(ClockAdjustment { mean, stddev })
            }
        }
    }

    pub fn monotonic_instant_from(&mut self, ts: TimeStamp) -> Instant {
        let instant = self.time_base.instant_from(ts);
        match self.last_monotonic_instant {
            Some(last) if last >= instant => last,
            _ => {
                self.last_monotonic_instant = Some(instant);
                instant
            }
        }
    }

    pub fn instant_from(&self, ts: TimeStamp) -> Instant {
        self.time_base.instant_from(ts)
    }
}

#[cfg(test)]
mod synchronized_remote_clock {
    use std::{cmp::Ordering, time::Duration};

    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn synchronize(drift_micros: i32) {
            const MAX_SAMPLES: i32 = 1000;
            let drift = TimeSpan::from_micros(drift_micros / 2);
            let start = Instant::now() + TimeSpan::MAX;
            let start_ts = TimeStamp::from_micros(100_000_000);
            let mut clock = SynchronizedRemoteClock::new(start);

            let adjustment = clock.synchronize(start, start_ts);
            prop_assert_eq!(adjustment, None, "the clock should be set, not adjusted, on the first sample");

            let instant = clock.instant_from(start_ts);
            prop_assert_eq!(instant, start, "the clock should be set on the first sample");

            for tick_ts in 1..1002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                let adjustment = clock.synchronize(now, now_ts);
                match tick_ts.cmp(&MAX_SAMPLES) {
                    Ordering::Less => prop_assert_eq!(adjustment, None, "the clock should not be adjusted until {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                    Ordering::Equal => prop_assert_eq!(adjustment, Some(ClockAdjustment { mean: drift, stddev: TimeSpan::ZERO }), "the clock should be adjusted after {} samples", MAX_SAMPLES),
                    Ordering::Greater => prop_assert_eq!(adjustment, None, "the clock should not be adjusted until the next {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                }

                let instant = clock.instant_from(now_ts);
                match tick_ts.cmp(&MAX_SAMPLES) {
                    Ordering::Less => prop_assert_eq!(instant, start + tick, "the clock should not be adjusted until {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                    Ordering::Equal => prop_assert_eq!(instant, now, "the clock should be adjusted after {} samples", MAX_SAMPLES),
                    Ordering::Greater => prop_assert_eq!(instant, now, "the clock should not be adjusted until the next {} samples: tick_ts = {}", MAX_SAMPLES, tick_ts),
                }
            }

            // simulate drift variance outside tolerance (+/- 5ms)
            for tick_ts in 1002..2002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                assert_eq!(
                    clock.synchronize(now, now_ts - TimeSpan::from_micros((tick_ts % 2) * 11000)),
                    None); // constant 5ms drift variance

                let instant = clock.instant_from(now_ts);
                prop_assert_eq!(instant, now, "the clock should not be adjusted: tick_ts = {}", tick_ts);
            }
        }
    }

    proptest! {
        #[test]
        fn monotonic_instant(drift_micros: i32) {
            let drift = TimeSpan::from_micros(drift_micros / 2);
            let start = Instant::now() + TimeSpan::MAX;
            let start_ts = TimeStamp::from_micros(100_000_000);
            let mut clock = SynchronizedRemoteClock::new(start);
            clock.synchronize(start, start_ts);

            let mut last_monotonic_instant = clock.monotonic_instant_from(start_ts);

            for tick_ts in 1..1002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);
                clock.synchronize(now, now_ts);

                let monotonic_instant = clock.monotonic_instant_from(now_ts);

                prop_assert!(monotonic_instant >= last_monotonic_instant);
                last_monotonic_instant = monotonic_instant;
            }
        }
    }
}
