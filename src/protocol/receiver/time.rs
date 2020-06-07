use std::time::{Duration, Instant};

use stats::OnlineStats;

use crate::protocol::{TimeBase, TimeSpan, TimeStamp};

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
                self.time_base.adjust(drift);
            }
            Some(stats) => {
                stats.add(drift.as_micros());

                if stats.len() < Self::MAX_SAMPLES {
                    return;
                }

                if stats.stddev() < self.tolerance.as_micros() as f64 {
                    self.time_base
                        .adjust(TimeSpan::from_micros(stats.mean() as i32));
                }
            }
        }
        self.stats = Some(OnlineStats::new());
    }

    pub fn instant_from(&self, now: Instant, ts: TimeStamp) -> Instant {
        self.time_base.instant_from(now, ts)
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
        fn synchronize(drift_ts in 1u64..5000000) {
            const MAX_SAMPLES: i32 = 1000;

            let drift = Duration::from_micros(drift_ts);
            let start = Instant::now();
            let start_ts = TimeStamp::from_micros(100_000_000);

            let mut clock = SynchronizedRemoteClock::new(start);

            clock.synchronize(start, start_ts);
            let instant = clock.instant_from(start, start_ts);

            assert_eq!(instant, start, "the clock should be adjusted on the first sample");

            for tick_ts in 1..1002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                clock.synchronize(now, now_ts);
                let instant = clock.instant_from(start, now_ts);

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
                let instant = clock.instant_from(start, now_ts);

                assert_eq!(instant, now, "the clock should not be adjusted: tick_ts = {}", tick_ts);
            }

        }
    }
}
