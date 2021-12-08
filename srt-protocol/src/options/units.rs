use std::{
    fmt::{Display, Formatter},
    ops::{Add, Deref, Div, Mul},
    time::Duration,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ByteCount(pub u64);

impl From<ByteCount> for u64 {
    fn from(value: ByteCount) -> Self {
        value.0
    }
}

impl From<ByteCount> for usize {
    fn from(value: ByteCount) -> Self {
        value.0 as usize
    }
}

impl Deref for ByteCount {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Mul<u64> for ByteCount {
    type Output = ByteCount;

    fn mul(self, rhs: u64) -> Self::Output {
        ByteCount(self.0 * rhs)
    }
}

impl Mul<ByteCount> for u64 {
    type Output = ByteCount;

    fn mul(self, rhs: ByteCount) -> Self::Output {
        ByteCount(self * rhs.0)
    }
}

impl Display for ByteCount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PacketCount(pub u64);

impl From<PacketCount> for u64 {
    fn from(value: PacketCount) -> Self {
        value.0
    }
}

impl From<PacketCount> for usize {
    fn from(value: PacketCount) -> Self {
        value.0 as usize
    }
}

impl Deref for PacketCount {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Mul<PacketCount> for ByteCount {
    type Output = ByteCount;

    fn mul(self, rhs: PacketCount) -> Self::Output {
        ByteCount(self.0 * rhs.0)
    }
}

impl Mul<ByteCount> for PacketCount {
    type Output = ByteCount;

    fn mul(self, rhs: ByteCount) -> Self::Output {
        rhs * self
    }
}

impl Display for PacketCount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DataRate(pub u64);

impl From<u64> for DataRate {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<DataRate> for u64 {
    fn from(value: DataRate) -> Self {
        value.0
    }
}

impl Deref for DataRate {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Mul<Duration> for DataRate {
    type Output = ByteCount;

    fn mul(self, rhs: Duration) -> Self::Output {
        let bytes_nearest_second = self.0 * rhs.as_secs() as u64;
        let bytes_scaled_for_nanos = (self.0 as usize).saturating_mul(rhs.subsec_nanos() as usize);
        let bytes_remaining_nanos = (bytes_scaled_for_nanos / 1_000_000_000) as u64;
        ByteCount(bytes_nearest_second + bytes_remaining_nanos)
    }
}

impl Mul<DataRate> for Duration {
    type Output = ByteCount;

    fn mul(self, rhs: DataRate) -> Self::Output {
        rhs * self
    }
}

impl DataRate {
    pub fn period_for(self, rhs: ByteCount) -> Option<Duration> {
        // multiply size to adjust data rate to microseconds (i.e. x 1,000,000)
        if rhs.0 > 0 {
            let period = rhs.0 * 1_000_000 / self.0;
            if period > 0 {
                return Some(Duration::from_micros(period as u64));
            }
        }
        None
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PacketRate(pub u64);

impl From<u64> for PacketRate {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<PacketRate> for u64 {
    fn from(value: PacketRate) -> Self {
        value.0
    }
}

impl Deref for PacketRate {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Mul<Duration> for PacketRate {
    type Output = PacketCount;

    fn mul(self, rhs: Duration) -> Self::Output {
        let packets_nearest_second = self.0 * rhs.as_secs() as u64;
        let packets_scaled_for_nanos =
            (self.0 as usize).saturating_mul(rhs.subsec_nanos() as usize);
        let packets_remaining_nanos = (packets_scaled_for_nanos / 1_000_000_000) as u64;
        PacketCount(packets_nearest_second + packets_remaining_nanos)
    }
}

impl Mul<PacketRate> for Duration {
    type Output = PacketCount;

    fn mul(self, rhs: PacketRate) -> Self::Output {
        rhs * self
    }
}

impl Div<PacketRate> for DataRate {
    type Output = ByteCount;

    fn div(self, rhs: PacketRate) -> Self::Output {
        ByteCount(self.0 / rhs.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Percent(pub u64);

impl From<u64> for Percent {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Percent> for u64 {
    fn from(value: Percent) -> Self {
        value.0
    }
}

impl Deref for Percent {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add<u64> for Percent {
    type Output = Percent;

    fn add(self, rhs: u64) -> Self::Output {
        Percent(self.0 + rhs)
    }
}

impl Add<Percent> for u64 {
    type Output = Percent;

    fn add(self, rhs: Percent) -> Self::Output {
        rhs + self
    }
}

impl Mul<DataRate> for Percent {
    type Output = DataRate;

    fn mul(self, rhs: DataRate) -> Self::Output {
        DataRate(self.0 * rhs.0 / 100)
    }
}

impl Mul<Percent> for DataRate {
    type Output = DataRate;

    fn mul(self, rhs: Percent) -> Self::Output {
        rhs * self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_rate_period_for_bytes() {
        let data_rate = DataRate(1_000_000);
        let byte_count = ByteCount(1_000);

        let period = data_rate.period_for(byte_count);

        assert_eq!(period, Some(Duration::from_millis(1)))
    }

    #[test]
    fn data_rate_and_duration_multiplication() {
        let data_rate = DataRate(1_000_000);
        let period = Duration::from_millis(1);

        let bytes = data_rate * period;

        assert_eq!(bytes, ByteCount(1_000))
    }

    #[test]
    fn packet_rate_and_duration_multiplication() {
        let packet_rate = PacketRate(1_000_000);
        let period = Duration::from_millis(1);

        let packets = packet_rate * period;

        assert_eq!(packets, PacketCount(1_000))
    }
}
