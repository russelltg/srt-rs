use std::cmp::{max, Ordering};
use std::num::Wrapping;
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::time::{Duration, Instant};
use std::u32;

pub mod connection;
pub mod handshake;
pub mod receiver;
pub mod sender;
pub mod stats;

/// Timestamp in us after creation
/// These wrap every 2^32 microseconds
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord)]
pub struct TimeStamp(Wrapping<u32>);

/// Signed duration in us, e.g. RTT
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct TimeSpan(i32);

const TIMESTAMP_MASK: u128 = u32::MAX as u128;

#[derive(Copy, Clone, Debug)]
pub struct TimeBase(Instant);

impl TimeSpan {
    pub fn from_micros(us: i32) -> Self {
        Self(us)
    }

    pub fn as_micros(self) -> i32 {
        self.0
    }

    pub fn abs(self) -> Self {
        Self(self.0.abs())
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1e6
    }
}

impl TimeStamp {
    pub fn from_micros(us: u32) -> Self {
        Self(Wrapping(us))
    }

    pub fn as_micros(self) -> u32 {
        (self.0).0
    }

    pub fn as_secs_f64(self) -> f64 {
        (self.0).0 as f64 / 1e6
    }

    pub fn as_duration(self) -> Duration {
        Duration::from_micros(u64::from(self.as_micros()))
    }
}

impl PartialOrd<TimeStamp> for TimeStamp {
    fn partial_cmp(&self, other: &TimeStamp) -> Option<Ordering> {
        // this is a "best effort" implementation, and goes for close
        // if timestamps are very far apart, this will not work (and cannot)
        Some((*self - *other).as_micros().cmp(&0))
    }
}

impl Add<TimeSpan> for TimeStamp {
    type Output = TimeStamp;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: TimeSpan) -> Self::Output {
        TimeStamp(if rhs.0 > 0 {
            self.0 + Wrapping(rhs.0 as u32)
        } else {
            self.0 - Wrapping(rhs.0.abs() as u32)
        })
    }
}

impl Sub<TimeSpan> for TimeStamp {
    type Output = TimeStamp;

    fn sub(self, rhs: TimeSpan) -> Self::Output {
        self + -rhs
    }
}

impl Sub<TimeStamp> for TimeStamp {
    type Output = TimeSpan;

    fn sub(self, rhs: TimeStamp) -> TimeSpan {
        // This is also a "best effort" implementation, and cannot be precise
        let pos_sub = self.0 - rhs.0;
        let neg_sub = rhs.0 - self.0;
        if pos_sub < neg_sub {
            TimeSpan(pos_sub.0 as i32)
        } else {
            -TimeSpan(neg_sub.0 as i32)
        }
    }
}

impl Neg for TimeSpan {
    type Output = TimeSpan;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Mul<i32> for TimeSpan {
    type Output = TimeSpan;

    fn mul(self, rhs: i32) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Add<TimeSpan> for TimeSpan {
    type Output = TimeSpan;

    fn add(self, rhs: TimeSpan) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Div<i32> for TimeSpan {
    type Output = TimeSpan;

    fn div(self, rhs: i32) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl Sub<TimeSpan> for TimeSpan {
    type Output = TimeSpan;

    fn sub(self, rhs: TimeSpan) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl TimeBase {
    pub fn new(start_time: Instant) -> Self {
        Self(start_time)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn timestamp_from(&self, instant: Instant) -> TimeStamp {
        assert!(
            self.0 <= instant,
            "Timestamps are only valid after the timebase start time"
        );
        TimeStamp(Wrapping(
            ((instant - self.0).as_micros() & TIMESTAMP_MASK) as u32,
        ))
    }

    // Get Instant closest to `now` that is consistent with `timestamp`
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn instant_from(&self, now: Instant, timestamp: TimeStamp) -> Instant {
        let wraps = ((now - self.0).as_micros() >> 32) as u64;
        self.0
            + Duration::from_micros(wraps * u64::from(std::u32::MAX) + timestamp.as_micros() as u64)
    }

    pub fn adjust(&mut self, delta: TimeSpan) {
        if delta.0 > 0 {
            self.0 += Duration::from_micros(delta.0 as u64);
        } else {
            self.0 -= Duration::from_micros(delta.0.abs() as u64);
        }
    }

    pub fn origin_time(&self) -> Instant {
        self.0
    }
}

#[cfg(test)]
mod timebase {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn timestamp_roundtrip(expected_ts: u32) {
            let timebase = TimeBase::new(Instant::now());
            let expected_ts = TimeStamp::from_micros(expected_ts);

            let ts = timebase.timestamp_from(timebase.instant_from(Instant::now(), expected_ts));
            assert_eq!(ts, expected_ts);
        }

        #[test]
        fn timestamp_from(expected_ts: u32, n in 0u64..10) {
            let now = Instant::now();
            let timebase = TimeBase::new(now);
            let delta = ((std::u32::MAX as u64 + 1)* n) + expected_ts as u64;
            let instant =  now + Duration::from_micros(delta as u64);
            let ts = timebase.timestamp_from(instant);
            assert_eq!(ts, TimeStamp::from_micros(expected_ts));
        }

        #[test]
        fn adjust(drift: i16) {
            let now = Instant::now();
            let mut timebase = TimeBase::new(now);
            let drift = TimeSpan::from_micros(i32::from(drift));

            let original_ts = timebase.timestamp_from(now);
            timebase.adjust(drift);
            let ts = timebase.timestamp_from(now + Duration::from_micros(1_000_000));

            assert_eq!(ts, original_ts - drift + TimeSpan::from_micros(1_000_000));
        }

    }
}

#[cfg(test)]
mod timestamp {
    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn subtract_timestamp() {
        let a = TimeStamp::from_micros(10);
        let max = a - TimeSpan(11);
        let b = TimeStamp::from_micros(11);

        assert_eq!(a - a, TimeSpan::from_micros(0));
        assert_eq!(b - a, TimeSpan::from_micros(1));
        assert_eq!(a - b, TimeSpan::from_micros(-1));
        assert!(max < a);
        assert!(b > a);
        assert!(b > max);
        assert_eq!(max.as_micros(), u32::MAX);
    }
}

//4. Timers
//
//   UDT uses four timers to trigger different periodical events. Each
//   event has its own period and they are all independent. They use the
//   system time as origins and should process wrapping if the system time
//   wraps.
//
//   For a certain periodical event E in UDT, suppose the time variable is
//   ET and its period is p. If E is set or reset at system time t0 (ET =
//   t0), then at any time t1, (t1 - ET >= p) is the condition to check if
//   E should be triggered.
//
//   The four timers are ACK, NAK, EXP and SND. SND is used in the sender
//   only for rate-based packet sending (see Section 6.1), whereas the
//   other three are used in the receiver only.
//
//   ACK is used to trigger an acknowledgement (ACK). Its period is set by
//   the congestion control module. However, UDT will send an ACK no
//   longer than every 0.01 second, even though the congestion control
//   does not need timer-based ACK. Here, 0.01 second is defined as the
//   SYN time, or synchronization time, and it affects many of the other
//   timers used in UDT.
//
//   NAK is used to trigger a negative acknowledgement (NAK). Its period
//   is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
//   variance of RTT samples.
//
//   EXP is used to trigger data packets retransmission and maintain
//   connection status. Its period is dynamically updated to 4 * RTT +
//   RTTVar + SYN.
//
//   The recommended granularity of their periods is microseconds. The
//   system time is queried after each time bounded UDP receiving (there
//   will be additional necessary data processing time if a UDP packet is
//   received) to check if any of the ACK, NAK, or EXP event should be
//   triggered. The timeout value of UDP receiving should be at least SYN.
//
//   In the rest of this document, a name of a time variable will be used
//   to represent the associated event, the variable itself, or the value
//   of its period, depending on the context. For example, ACK can mean
//   either the ACK event or the value of ACK period.

pub struct Timer {
    period: Duration,
    last: Instant,
}

impl Timer {
    const MIN_PERIOD: Duration = Duration::from_micros(1);

    pub fn new(period: Duration, now: Instant) -> Timer {
        Timer {
            period: max(period, Self::MIN_PERIOD),
            last: now,
        }
    }

    pub fn period(&mut self) -> Duration {
        self.period
    }

    pub fn next_instant(&self) -> Instant {
        self.last + self.period
    }

    pub fn reset(&mut self, now: Instant) {
        self.last = now;
    }

    pub fn set_period(&mut self, period: Duration) {
        self.period = period;
    }

    pub fn check_expired(&mut self, now: Instant) -> Option<Instant> {
        if now > self.next_instant() {
            self.last = self.next_instant();
            Some(self.last)
        } else {
            None
        }
    }
}
