use std::{
    ops::{Div, Mul},
    time::Duration,
};

use derive_more::*;

#[derive(Debug, Deref, Display, Into, Mul, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0} bytes")]
pub struct ByteCount(pub u64);

impl From<ByteCount> for usize {
    fn from(value: ByteCount) -> Self {
        value.0 as usize
    }
}

impl Div<PacketSize> for ByteCount {
    type Output = PacketCount;

    fn div(self, rhs: PacketSize) -> Self::Output {
        PacketCount(self.0 / rhs.0)
    }
}

#[derive(Debug, Deref, Display, Into, Add, Sub, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0} bytes")]
pub struct PacketSize(pub u64);

impl From<PacketSize> for usize {
    fn from(value: PacketSize) -> Self {
        value.0 as usize
    }
}

#[derive(Debug, Deref, Display, Into, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0} packets")]
pub struct PacketCount(pub u64);

impl From<PacketCount> for usize {
    fn from(value: PacketCount) -> Self {
        value.0 as usize
    }
}

impl Mul<PacketCount> for PacketSize {
    type Output = ByteCount;

    fn mul(self, rhs: PacketCount) -> Self::Output {
        ByteCount(self.0 * rhs.0)
    }
}

impl Mul<PacketSize> for PacketCount {
    type Output = ByteCount;

    fn mul(self, rhs: PacketSize) -> Self::Output {
        rhs * self
    }
}

impl PacketCount {
    pub fn for_time_window(window: Duration, packet_spacing: Duration) -> PacketCount {
        PacketCount((window.as_micros() / packet_spacing.as_micros()) as u64)
    }
}

#[derive(Debug, Deref, Display, Into, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0} bytes/s")]
pub struct DataRate(pub u64);

impl Mul<Duration> for DataRate {
    type Output = ByteCount;

    fn mul(self, rhs: Duration) -> Self::Output {
        let bytes_nearest_second = self.0 * rhs.as_secs();
        let bytes_scaled_for_micros = self.0.saturating_mul(u64::from(rhs.subsec_micros()));
        let bytes_remaining_micros = bytes_scaled_for_micros / 1_000_000;
        ByteCount(bytes_nearest_second + bytes_remaining_micros)
    }
}

impl Mul<DataRate> for Duration {
    type Output = ByteCount;

    fn mul(self, rhs: DataRate) -> Self::Output {
        rhs * self
    }
}

impl DataRate {
    pub fn as_mbps_f64(&self) -> f64 {
        self.0 as f64 / 1_000_000.
    }
}

#[derive(Debug, Deref, Display, Into, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0} packets/s")]
pub struct PacketRate(pub u64);

impl Mul<Duration> for PacketRate {
    type Output = PacketCount;

    fn mul(self, rhs: Duration) -> Self::Output {
        let packets_nearest_second = self.0 * rhs.as_secs();
        let packets_scaled_for_micros =
            (self.0 as usize).saturating_mul(rhs.subsec_micros() as usize);
        let packets_remaining_micros = (packets_scaled_for_micros / 1_000_000) as u64;
        PacketCount(packets_nearest_second + packets_remaining_micros)
    }
}

impl Mul<PacketRate> for Duration {
    type Output = PacketCount;

    fn mul(self, rhs: PacketRate) -> Self::Output {
        rhs * self
    }
}

impl Div<PacketRate> for DataRate {
    type Output = PacketSize;

    fn div(self, rhs: PacketRate) -> Self::Output {
        PacketSize(self.0 / rhs.0)
    }
}

#[derive(Debug, Deref, Display, Into, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{} s/p", "_0.as_secs_f64()")]
pub struct PacketPeriod(pub Duration);

impl Mul<PacketCount> for PacketPeriod {
    type Output = Duration;

    fn mul(self, rhs: PacketCount) -> Self::Output {
        self.0 * rhs.0 as u32
    }
}

impl Mul<PacketPeriod> for PacketCount {
    type Output = Duration;

    fn mul(self, rhs: PacketPeriod) -> Self::Output {
        rhs * self
    }
}

impl PacketPeriod {
    pub fn try_from(data_rate: DataRate, packet_size: PacketSize) -> Option<Duration> {
        // multiply size to adjust data rate to microseconds (i.e. x 1,000,000)
        if packet_size.0 > 0 {
            let period = packet_size.0 * 1_000_000 / data_rate.0;
            if period > 0 {
                return Some(Duration::from_micros(period));
            }
        }
        None
    }
}

#[derive(Debug, Deref, Display, Into, Add, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{_0}%")]
pub struct Percent(pub u64);

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

    #[test]
    fn packet_period_from_data_rate_and_packet_size() {
        let data_rate = DataRate(20_000);
        let packet_size = PacketSize(500);

        let period = PacketPeriod::try_from(data_rate, packet_size);

        assert_eq!(period, Some(Duration::from_millis(25)))
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", ByteCount(100)), "100 bytes");
        assert_eq!(format!("{}", PacketSize(100)), "100 bytes");
        assert_eq!(format!("{}", PacketCount(100)), "100 packets");
        assert_eq!(format!("{}", DataRate(100)), "100 bytes/s");
        assert_eq!(format!("{}", PacketRate(100)), "100 packets/s");
        assert_eq!(format!("{}", Percent(100)), "100%");
    }
}
