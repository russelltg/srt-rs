use std::cmp::{max, min};
use std::time::{Duration, Instant};

use stats::OnlineStats;

use crate::protocol::{TimeBase, TimeSpan, TimeStamp, Timer};

pub(crate) struct SynchronizedRemoteClock {
    drift_deviation_tolerance: Duration,
    time_base: TimeBase,
    last_monotonic_instant: Option<Instant>,
    stats: Option<OnlineStats>,
}

impl SynchronizedRemoteClock {
    const MAX_SAMPLES: usize = 1_000;
    const DRIFT_DEVIATION_TOLERANCE: Duration = Duration::from_millis(5);

    pub fn new(now: Instant) -> Self {
        Self {
            // TODO: Drift deviation tolerance should be parameterized.
            //       It wasn't in the reference implementation, but I added it because the reference
            //       implementation is susceptible to invalid clock adjustments during periods of
            //       acute network latency
            drift_deviation_tolerance: Self::DRIFT_DEVIATION_TOLERANCE,
            time_base: TimeBase::new(now),
            last_monotonic_instant: None,
            stats: None,
        }
    }

    pub fn synchronize(&mut self, now: Instant, ts: TimeStamp) {
        let drift = self.time_base.timestamp_from(now) - ts;
        match &mut self.stats {
            None => {
                self.time_base.adjust(now, drift);
            }
            Some(stats) => {
                stats.add(drift.as_micros());

                if stats.len() < Self::MAX_SAMPLES {
                    return;
                }

                if stats.stddev() < self.drift_deviation_tolerance.as_micros() as f64 {
                    self.time_base
                        .adjust(now, TimeSpan::from_micros(stats.mean() as i32));
                }
            }
        }
        self.stats = Some(OnlineStats::new());
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
        fn synchronize(drift_micros: i32) {
            const MAX_SAMPLES: i32 = 1000;
            let drift = TimeSpan::from_micros(drift_micros / 2);
            let start = Instant::now() + TimeSpan::MAX;
            let start_ts = TimeStamp::from_micros(100_000_000);
            let mut clock = SynchronizedRemoteClock::new(start);

            clock.synchronize(start, start_ts);

            let instant = clock.instant_from(start_ts);
            prop_assert_eq!(instant, start, "the clock should be adjusted on the first sample");

            for tick_ts in 1..1002 {
                let tick = Duration::from_micros(tick_ts as u64);
                let now = start + tick + drift;
                let now_ts = start_ts + TimeSpan::from_micros(tick_ts);

                clock.synchronize(now, now_ts);

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

                clock.synchronize(now, now_ts - TimeSpan::from_micros((tick_ts % 2) * 11000)); // constant 5ms drift variance

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

#[derive(Debug)]
pub(crate) struct Rtt {
    mean: TimeSpan,
    variance: TimeSpan,
}

impl Rtt {
    pub fn new() -> Self {
        Self {
            mean: TimeSpan::from_micros(10_000),
            variance: TimeSpan::from_micros(1_000),
        }
    }

    pub fn update(&mut self, rtt: TimeSpan) {
        self.mean = TimeSpan::from_micros(
            ((self.mean.as_micros() as i64 * 7 + rtt.as_micros() as i64) / 8) as i32,
        );
        self.variance = TimeSpan::from_micros(
            ((self.variance.as_micros() as i64 * 3
                + (self.mean.as_micros() as i64 - rtt.as_micros() as i64).abs() as i64)
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
        Duration::from_micros(self.mean.as_micros() as u64)
    }

    pub fn variance_as_duration(&self) -> Duration {
        Duration::from_micros(self.variance.as_micros() as u64)
    }
}

//   The recommended granularity of their periods is microseconds. The
//   system time is queried after each time bounded UDP receiving (there
//   will be additional necessary data processing time if a UDP packet is
//   received) to check if any of the ACK, NAK, or EXP event should be
//   triggered. The timeout value of UDP receiving should be at least SYN.
#[derive(Debug)]
pub(crate) struct ReceiveTimers {
    //   ACK is used to trigger an acknowledgement (ACK). Its period is set by
    //   the congestion control module. However, UDT will send an ACK no
    //   longer than every 0.01 second, even though the congestion control
    //   does not need timer-based ACK. Here, 0.01 second is defined as the
    //   SYN time, or synchronization time, and it affects many of the other
    //   timers used in UDT.
    ack: Timer,

    //   NAK is used to trigger a negative acknowledgement (NAK). Its period
    //   is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
    //   variance of RTT samples.
    nak: Timer,

    //   EXP is used to trigger data packets retransmission and maintain
    //   connection status. Its period is dynamically updated to 4 * RTT +
    //   RTTVar + SYN.
    exp: Timer,
    exp_count: u32,
    last_input: Instant,
    peer_idle_timeout: Duration,
}

impl ReceiveTimers {
    const SYN: Duration = Duration::from_millis(10);
    const EXP_MAX: u32 = 16;

    pub fn new(now: Instant) -> ReceiveTimers {
        let (ack, nak, exp) = Self::calculate_periods(1, &Rtt::new());
        ReceiveTimers {
            ack: Timer::new(ack, now),
            nak: Timer::new(nak, now),
            exp: Timer::new(exp, now),
            exp_count: 1,
            last_input: now,
            peer_idle_timeout: Duration::from_secs(5),
        }
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        max(
            now,
            min(
                self.nak.next_instant(),
                min(self.ack.next_instant(), self.exp.next_instant()),
            ),
        )
    }

    pub fn check_ack(&mut self, now: Instant) -> Option<Instant> {
        self.ack.check_expired(now)
    }

    pub fn check_nak(&mut self, now: Instant) -> Option<Instant> {
        self.nak.check_expired(now)
    }

    pub fn check_peer_idle_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.exp.check_expired(now)?;

        let peer_idle = now - self.last_input;
        if self.exp_count > Self::EXP_MAX && peer_idle > self.peer_idle_timeout {
            Some(self.last_input)
        } else {
            self.exp_count += 1;
            None
        }
    }

    pub fn on_input(&mut self, now: Instant) {
        self.exp_count = 1;
        self.last_input = now;
    }

    pub fn update_rtt(&mut self, rtt: &Rtt) {
        let (ack, nak, exp) = Self::calculate_periods(self.exp_count, rtt);
        self.ack.set_period(ack);
        self.nak.set_period(nak);
        self.exp.set_period(exp);
    }

    fn calculate_periods(exp_count: u32, rtt: &Rtt) -> (Duration, Duration, Duration) {
        let ms = Duration::from_millis;
        let rtt_period = 4 * rtt.mean_as_duration() + rtt.variance_as_duration() + Self::SYN;

        let ack_period = rtt_period;

        let nak_report_period_accelerator: u32 = 2;
        let nak_period = nak_report_period_accelerator * rtt_period;

        // 0.5s minimum, according to page 9
        // but 0.3s in reference implementation
        let exp_period = max(exp_count * rtt_period, exp_count * ms(300));

        (ack_period, nak_period, exp_period)
    }
}

#[cfg(test)]
mod receive_timers {
    use super::*;
    use proptest::prelude::*;

    fn diff(a: Instant, b: Instant) -> Duration {
        if a > b {
            a - b
        } else {
            b - a
        }
    }

    #[test]
    fn next_timer() {
        let ms = Duration::from_millis;
        let rtt_mean = ms(10);
        let rtt_variance = ms(1);
        let syn = ms(10);
        let start = Instant::now();
        let mut timers = ReceiveTimers::new(start);

        // next timer should be ack
        // 4 * RTT + RTTVar + SYN
        let ack = 4 * rtt_mean + rtt_variance + syn;
        let now = start;
        let actual_timer = timers.next_timer(now);
        assert_eq!(diff(actual_timer, now), ack);

        // only ack timer should fire
        assert!(timers.check_ack(actual_timer).is_some());
        assert!(timers.check_nak(actual_timer).is_none());
        assert!(timers.check_peer_idle_timeout(actual_timer).is_none());

        // next timer should be nak
        // NAK accelerator * 4 * RTT + RTTVar + SYN
        let nak = 2 * (4 * rtt_mean + rtt_variance + syn);
        let now = actual_timer;
        let actual_timer = timers.next_timer(now);
        assert_eq!(diff(actual_timer, start), nak);

        // both ack and nak should fire because their periods overlap
        assert!(timers.check_ack(actual_timer).is_some());
        assert!(timers.check_nak(actual_timer).is_some());
        assert!(timers.check_peer_idle_timeout(actual_timer).is_none());

        // exp will have a lower bound period of 500ms
        let exp_lower_bound = ms(300);
        let now = start + exp_lower_bound;

        // push time forward for ack and nak first
        assert!(timers.check_ack(now).is_some());
        assert!(timers.check_nak(now).is_some());

        // next timer should be exp
        let actual_timer = timers.next_timer(now);
        assert_eq!(diff(actual_timer, start), exp_lower_bound);

        // exp timer should fire
        assert!(timers.check_ack(actual_timer).is_none());
        assert!(timers.check_nak(actual_timer).is_none());

        let last_input = start;
        timers.on_input(last_input);
        for exp_count in 1..=16 {
            assert!(timers
                .check_peer_idle_timeout(last_input + exp_count * exp_lower_bound)
                .is_none());
        }
        assert!(timers
            .check_peer_idle_timeout(last_input + 17 * exp_lower_bound)
            .is_some());
    }

    proptest! {
        #[test]
        fn update_rtt(simulated_rtt in 45_000i32..) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = Rtt::new();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // above lower bound of exp
            prop_assume!(4 * rtt_mean + rtt_variance + syn > ms(300));

            let start = Instant::now();
            let mut timers = ReceiveTimers::new(start);

            timers.update_rtt(&rtt);

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.ack.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);

            // NAK accelerator * 4 * RTT + RTTVar + SYN
            assert_eq!(timers.nak.next_instant() - start, 2 * (4 * rtt_mean + rtt_variance + syn));

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.exp.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);
        }

        #[test]
        fn update_rtt_exp_lower_bound(simulated_rtt in 0i32..50_000) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = Rtt::new();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // below lower bound of exp
            prop_assume!(4 * rtt_mean + rtt_variance + syn <= ms(300));

            let start = Instant::now();
            let mut timers = ReceiveTimers::new(start);

            timers.update_rtt(&rtt);

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.ack.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);

            // NAK accelerator * 4 * RTT + RTTVar + SYN
            assert_eq!(timers.nak.next_instant() - start, 2 * (4 * rtt_mean + rtt_variance + syn));

            // exp has a lower bound period of 300ms
            assert_eq!(timers.exp.next_instant() - start, ms(300));
        }
    }
}
