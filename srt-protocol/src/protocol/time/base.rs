use std::time::Instant;

use crate::packet::{TimeSpan, TimeStamp};

#[derive(Copy, Clone, Debug)]
pub struct TimeBase {
    // this field is only here for diagnostics and debugging
    // it is similar to start_time in other contexts, but is adjusted for drift
    origin_time: Instant,

    // the two "reference" fields are two equivalent time points from different
    // time scales they are reference points used for mapping between the Instance
    // and a sender TimeStamp time scales
    reference_time: Instant,
    reference_ts: TimeStamp,
}

impl TimeBase {
    pub fn new(start_time: Instant) -> Self {
        Self {
            origin_time: start_time,
            reference_time: start_time,
            reference_ts: TimeStamp::MIN,
        }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn timestamp_from(&self, instant: Instant) -> TimeStamp {
        if instant < self.reference_time {
            self.reference_ts - (self.reference_time - instant)
        } else {
            self.reference_ts + (instant - self.reference_time)
        }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn instant_from(&self, timestamp: TimeStamp) -> Instant {
        self.reference_time + (timestamp - self.reference_ts)
    }

    #[allow(clippy::assign_op_pattern)]
    pub fn adjust(&mut self, now: Instant, drift: TimeSpan) {
        self.origin_time = self.origin_time - drift;
        self.reference_time = self.reference_time - drift;

        if now > self.reference_time {
            let delta = now - self.reference_time;
            self.reference_time = self.reference_time + delta;
            self.reference_ts = self.reference_ts + delta;
        }
    }

    pub fn origin_time(&self) -> Instant {
        self.origin_time
    }
}

#[cfg(test)]
mod timebase {
    use proptest::prelude::*;

    use super::*;

    use std::time::Duration;

    proptest! {
        #[test]
        fn timestamp_roundtrip(expected_ts: u32) {
            let timebase = TimeBase::new(Instant::now() + Duration::from_micros(expected_ts as u64));
            let expected_ts = TimeStamp::from_micros(expected_ts);

            let ts = timebase.timestamp_from(timebase.instant_from(expected_ts));

            prop_assert_eq!(ts, expected_ts);
        }

        #[test]
        fn timestamp_from(expected_offset: i32, n in -2..2) {
            let expected_offset = TimeSpan::from_micros(expected_offset / 2);
            let now = Instant::now() + Duration::from_micros(u32::MAX as u64) * 3;
            let timebase = TimeBase::new(now);
            // adjust the test instant time enough so that
            // 1) underflow and overflow are avoided
            // 2) TimeStamp rollover is covered
            let adjustment = ((std::u32::MAX as u64 + 1) as i64) * (n as i64);
            let instant = if adjustment > 0 {
                now + Duration::from_micros(adjustment as u64) + expected_offset
            } else {
                now - Duration::from_micros(-adjustment as u64) + expected_offset
            };

            let ts = timebase.timestamp_from(instant);

            prop_assert_eq!(ts, TimeStamp::MIN + expected_offset);
        }

        #[test]
        fn adjust(drift: i16, clock_delta: i16) {
            let start = Instant::now();
            let drift = TimeSpan::from_micros(drift as i32);
            let clock_delta = TimeSpan::from_micros(clock_delta as i32);
            let mut timebase = TimeBase::new(start);
            let original_ts = timebase.timestamp_from(start);
            let now = start + clock_delta;

            timebase.adjust(now, drift);

            let original_time = timebase.instant_from(original_ts);
            assert_eq!(start - drift - original_time, Duration::from_micros(0));

            let ts = timebase.timestamp_from(start);
            prop_assert_eq!(ts, original_ts - drift);
        }
    }

    #[test]
    fn timestamp_from_past() {
        let now = Instant::now() + Duration::from_micros(u32::MAX as u64);
        let timebase = TimeBase::new(now);

        let ts = timebase.timestamp_from(now + TimeSpan::MIN);

        assert_eq!(ts, TimeStamp::MIN + TimeSpan::MIN);
    }

    #[test]
    fn timestamp_from_future() {
        let now = Instant::now();
        let timebase = TimeBase::new(now);

        let ts = timebase.timestamp_from(now + TimeSpan::MAX);

        assert_eq!(ts, TimeStamp::MIN + TimeSpan::MAX);
    }
}
