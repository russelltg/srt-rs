use std::cmp::{max, Ordering};
use std::fmt;
use std::num::Wrapping;
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::time::{Duration, Instant};
use std::u32;

pub mod handshake;
pub mod receiver;
pub mod sender;
pub mod stats;

/// Timestamp in us after creation
/// These wrap every 2^32 microseconds
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TimeStamp(Wrapping<u32>);

/// Signed duration in us, e.g. RTT
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct TimeSpan(i32);

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

impl TimeSpan {
    pub const MAX: TimeSpan = TimeSpan::from_micros(i32::MAX);
    pub const MIN: TimeSpan = TimeSpan::from_micros(i32::MIN);
    pub const ZERO: TimeSpan = TimeSpan::from_micros(0);

    pub fn from_interval(begin: Instant, end: Instant) -> Self {
        if begin <= end {
            Self::ZERO + (end - begin)
        } else {
            Self::ZERO - (begin - end)
        }
    }

    pub const fn from_micros(us: i32) -> Self {
        Self(us)
    }

    pub const fn from_millis(us: i32) -> Self {
        Self(us * 1_000)
    }

    pub const fn as_micros(self) -> i32 {
        self.0
    }

    pub const fn abs(self) -> Self {
        Self(self.0.abs())
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1e6
    }
}

impl TimeStamp {
    pub const MAX: TimeStamp = TimeStamp::from_micros(u32::MAX);
    pub const MIN: TimeStamp = TimeStamp::from_micros(u32::MIN);

    pub const fn from_micros(us: u32) -> Self {
        Self(Wrapping(us))
    }

    pub const fn as_micros(self) -> u32 {
        (self.0).0
    }
}

impl fmt::Debug for TimeStamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let time = (self.0).0;
        let mins = time / 1_000_000 / 60 % 60;
        let secs = time / 1_000_000 % 60;
        let micros = time % 1_000_000;
        write!(f, "{:02}:{:02}.{:06}", mins, secs, micros)
    }
}

impl PartialOrd<TimeStamp> for TimeStamp {
    fn partial_cmp(&self, other: &TimeStamp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeStamp {
    fn cmp(&self, other: &Self) -> Ordering {
        // this is a "best effort" implementation, and goes for close
        // if timestamps are very far apart, this will not work (and cannot)
        (*self - *other).as_micros().cmp(&0)
    }
}

impl Add<TimeSpan> for TimeStamp {
    type Output = TimeStamp;

    fn add(self, rhs: TimeSpan) -> Self::Output {
        if rhs < TimeSpan::ZERO {
            TimeStamp(self.0 - Wrapping((rhs.0 as i64).abs() as u32))
        } else {
            TimeStamp(self.0 + Wrapping(rhs.0 as u32))
        }
    }
}

impl Sub<TimeSpan> for TimeStamp {
    type Output = TimeStamp;

    fn sub(self, rhs: TimeSpan) -> Self::Output {
        if rhs < TimeSpan::ZERO {
            TimeStamp(self.0 + Wrapping((rhs.0 as i64).abs() as u32))
        } else {
            TimeStamp(self.0 - Wrapping(rhs.0 as u32))
        }
    }
}

impl Add<Duration> for TimeStamp {
    type Output = TimeStamp;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + Wrapping(rhs.as_micros() as u32))
    }
}

impl Sub<Duration> for TimeStamp {
    type Output = TimeStamp;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - Wrapping(rhs.as_micros() as u32))
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

impl fmt::Debug for TimeSpan {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let sign = if self.0 < 0 { "-" } else { "" };
        let mins = self.0.abs() / 1_000_000 / 60 % 60;
        let secs = self.0.abs() / 1_000_000 % 60;
        let micros = self.0.abs() % 1_000_000;
        write!(f, "{}{:02}:{:02}.{:06}", sign, mins, secs, micros)
    }
}

impl From<Duration> for TimeSpan {
    fn from(duration: Duration) -> TimeSpan {
        TimeSpan::from_micros(duration.as_micros() as i32)
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

impl Mul<TimeSpan> for i32 {
    type Output = TimeSpan;

    fn mul(self, rhs: TimeSpan) -> Self::Output {
        TimeSpan(self * rhs.0)
    }
}

impl Div<i32> for TimeSpan {
    type Output = TimeSpan;

    fn div(self, rhs: i32) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl Add<TimeSpan> for TimeSpan {
    type Output = TimeSpan;

    fn add(self, rhs: TimeSpan) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub<TimeSpan> for TimeSpan {
    type Output = TimeSpan;

    fn sub(self, rhs: TimeSpan) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Add<Duration> for TimeSpan {
    type Output = TimeSpan;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_micros() as i32)
    }
}

impl Sub<Duration> for TimeSpan {
    type Output = TimeSpan;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.as_micros() as i32)
    }
}

impl Add<TimeSpan> for Instant {
    type Output = Instant;

    fn add(self, rhs: TimeSpan) -> Self::Output {
        let micros = rhs.as_micros() as i64;
        if micros > 0 {
            self + Duration::from_micros(micros as u64)
        } else {
            self - Duration::from_micros(micros.abs() as u64)
        }
    }
}

impl Sub<TimeSpan> for Instant {
    type Output = Instant;

    fn sub(self, rhs: TimeSpan) -> Self::Output {
        let micros = rhs.as_micros() as i64;
        if micros > 0 {
            self + Duration::from_micros(micros as u64)
        } else {
            self - Duration::from_micros(micros.abs() as u64)
        }
    }
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
    use super::*;
    use proptest::prelude::*;

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

#[cfg(test)]
mod timestamp {
    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn timestamp_operators() {
        let ts = TimeStamp::from_micros(u32::MAX >> 1);
        let a = ts + Duration::from_micros(10);
        let b = ts + Duration::from_micros(11);

        assert_eq!(a - a, TimeSpan::ZERO);
        assert_eq!(b - a, TimeSpan::from_micros(1));
        assert_eq!(a - b, TimeSpan::from_micros(-1));
        assert!(b > a);

        let max = TimeStamp::MIN - TimeSpan::from_micros(1);
        let min = TimeStamp::MAX + TimeSpan::from_micros(1);
        assert_eq!(max.as_micros(), u32::MAX);
        assert_eq!(min.as_micros(), u32::MIN);
        assert_eq!(max - min, TimeSpan::from_micros(-1));
        assert_eq!(min - max, TimeSpan::from_micros(1));
        assert!(max > a);
        assert!(b < max);
        // this is counter intuitive, but a modulo counter wraps
        //  so max + 1 == min and max + 1 > max
        assert!(min > max);
        assert!(max < min);
    }

    #[test]
    fn debug_fmt() {
        assert_eq!("00:00.000001", format!("{:?}", TimeStamp::from_micros(1)));
        assert_eq!(
            "01:02.030040",
            format!("{:?}", TimeStamp::from_micros(62030040))
        );
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

#[derive(Debug)]
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
        if self.period.as_nanos() == 0 {
            return Some(now);
        }
        if now >= self.next_instant() {
            let elapsed = now - self.last;
            let elapsed_periods = elapsed.as_nanos() / self.period.as_nanos();
            self.last += self.period * elapsed_periods as u32;
            Some(self.last)
        } else {
            None
        }
    }
}
