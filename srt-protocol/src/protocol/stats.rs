use std::time::{Duration, Instant};

pub(crate) trait Stats: Default {
    type Measure;

    fn add(&mut self, measure: Self::Measure);
}

pub(crate) struct StatsWindow<T: Stats> {
    pub period: Duration,
    pub stats: T,
}

impl<T: Stats> Default for StatsWindow<T> {
    fn default() -> Self {
        Self {
            period: Duration::from_secs(1),
            stats: T::default(),
        }
    }
}

pub(crate) struct OnlineWindowedStats<T: Stats> {
    period: Duration,
    last: Option<Instant>,
    stats: T,
}

impl<T: Stats> OnlineWindowedStats<T> {
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            last: None,
            stats: Default::default(),
        }
    }

    pub fn add(&mut self, now: Instant, measure: T::Measure) -> Option<StatsWindow<T>> {
        self.stats.add(measure);

        match self.last {
            None => {
                self.last = Some(now);
                None
            }
            Some(last) => {
                if now < last + self.period {
                    None
                } else {
                    let elapsed = now - last;
                    self.last = Some(now);
                    Some(StatsWindow {
                        period: elapsed,
                        stats: std::mem::take(&mut self.stats),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod online_windowed_stats {
    use super::*;

    use std::ops::AddAssign;

    impl Stats for usize {
        type Measure = usize;

        fn add(&mut self, measure: Self::Measure) {
            self.add_assign(measure);
        }
    }

    #[test]
    fn add() {
        let ms = Duration::from_millis;
        let start = Instant::now();
        let mut stats = OnlineWindowedStats::<usize>::new(ms(1_000));

        stats.add(start, 0);

        let window = (1..3001)
            .flat_map(|n| {
                stats
                    .add(start + ms(n), 1)
                    .map(|window| (window.period, window.stats))
            })
            .collect::<Vec<_>>();

        assert_eq!(
            window,
            vec![
                (ms(1000), 1000_usize),
                (ms(1000), 1000_usize),
                (ms(1000), 1000_usize)
            ]
        );
    }
}
