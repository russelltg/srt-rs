use std::{
    cmp::Ordering,
    convert::TryInto,
    fmt,
    num::Wrapping,
    ops::{Add, Div, Mul, Neg, Sub},
    time::{Duration, Instant},
    u32,
};

/// Timestamp in us after creation
/// These wrap every 2^32 microseconds
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TimeStamp(Wrapping<u32>);

/// Signed duration in us, e.g. RTT
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct TimeSpan(i32);

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
        TimeSpan::from_micros(duration.as_micros().try_into().unwrap())
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
