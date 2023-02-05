use std::{convert::TryInto, time::Duration};

use crate::packet::TimeSpan;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Rtt {
    mean: TimeSpan,
    variance: TimeSpan,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            mean: TimeSpan::from_micros(10_000),
            variance: TimeSpan::from_micros(1_000),
        }
    }
}

impl Rtt {
    pub fn new(mean: TimeSpan, variance: TimeSpan) -> Self {
        Self { mean, variance }
    }

    pub fn update(&mut self, rtt: TimeSpan) {
        self.mean = TimeSpan::from_micros(
            ((self.mean.as_micros() as i64 * 7 + rtt.as_micros() as i64) / 8) as i32,
        );
        self.variance = TimeSpan::from_micros(
            ((self.variance.as_micros() as i64 * 3
                + (self.mean.as_micros() as i64 - rtt.as_micros() as i64).abs())
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
        Duration::from_micros(self.mean.as_micros().try_into().unwrap())
    }

    pub fn variance_as_duration(&self) -> Duration {
        Duration::from_micros(self.variance.as_micros().try_into().unwrap())
    }
}
