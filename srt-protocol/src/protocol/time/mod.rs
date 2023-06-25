mod base;
mod rtt;
mod timer;

pub use base::*;
pub use rtt::*;
pub use timer::*;

use std::{
    cmp::{max, min},
    time::{Duration, Instant},
};

//   The recommended granularity of their periods is microseconds. The
//   system time is queried after each time bounded UDP receiving (there
//   will be additional necessary data processing time if a UDP packet is
//   received) to check if any of the ACK, NAK, or EXP event should be
//   triggered. The timeout value of UDP receiving should be at least SYN.
#[derive(Debug)]
pub struct Timers {
    snd: Timer,

    //   ACK is used to trigger an acknowledgement (ACK). Its period is set by
    //   the congestion control module. However, UDT will send an ACK no
    //   longer than every 0.01 second, even though the congestion control
    //   does not need timer-based ACK. Here, 0.01 second is defined as the
    //   SYN time, or synchronization time, and it affects many of the other
    //   timers used in UDT.
    full_ack: Timer,

    //   NAK is used to trigger a negative acknowledgement (NAK). Its period
    //   is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
    //   variance of RTT samples.
    nak: Timer,

    //   EXP is used to trigger data packets retransmission and maintain
    //   connection status. Its period is dynamically updated to 4 * RTT +
    //   RTTVar + SYN.
    exp: Timer,
    exp_count: u32,
    peer_idle: Timer,

    statistics: Timer,
}

impl Timers {
    pub const SYN: Duration = Duration::from_millis(10);
    const EXP_MAX: u32 = 16;

    pub fn new(now: Instant, statistics_interval: Duration, peer_idle_timeout: Duration) -> Self {
        let (ack, nak, exp) = Self::calculate_periods(1, &Rtt::default());
        Self {
            snd: Timer::new(now, Duration::from_millis(1)),
            full_ack: Timer::new(now, ack),
            nak: Timer::new(now, nak),
            exp: Timer::new(now, exp),
            exp_count: 1,
            peer_idle: Timer::new(now, peer_idle_timeout),
            // this isn't in the spec, but it's in the reference implementation
            // https://github.com/Haivision/srt/blob/1d7b391905d7e344d80b86b39ac5c90fda8764a9/srtcore/core.cpp#L10610-L10614
            statistics: Timer::new(now, statistics_interval),
        }
    }

    pub fn next_timer(
        &self,
        now: Instant,
        has_packets_to_send: bool,
        next_message: Option<Instant>,
        unacked_packets: u32,
    ) -> Instant {
        let timer = min(self.exp.next_instant(), self.nak.next_instant());
        let timer = next_message.map_or(timer, |message| min(timer, message));
        let timer = if unacked_packets > 0 {
            min(self.full_ack.next_instant(), timer)
        } else {
            timer
        };
        let timer = if has_packets_to_send {
            min(self.snd.next_instant(), timer)
        } else {
            timer
        };

        max(now, timer)
    }

    pub fn check_snd(&mut self, now: Instant) -> Option<u32> {
        self.snd.check_expired(now)
    }

    pub fn check_full_ack(&mut self, now: Instant) -> Option<u32> {
        self.full_ack.check_expired(now)
    }

    pub fn check_nak(&mut self, now: Instant) -> Option<u32> {
        self.nak.check_expired(now)
    }

    pub fn check_peer_idle_timeout(&mut self, now: Instant) -> Option<u32> {
        let _ = self.exp.check_expired(now)?;

        self.peer_idle
            .check_expired(now)
            .filter(|_| self.exp_count > Self::EXP_MAX)
            .or_else(|| {
                self.exp_count += 1;
                None
            })
    }

    pub fn check_statistics(&mut self, now: Instant) -> Option<u32> {
        self.statistics.check_expired(now)
    }

    pub fn update_snd_period(&mut self, period: Duration) {
        self.snd.set_period(period)
    }

    pub fn update_rtt(&mut self, rtt: &Rtt) {
        let (ack, nak, exp) = Self::calculate_periods(self.exp_count, rtt);
        self.full_ack.set_period(ack);
        self.nak.set_period(nak);
        self.exp.set_period(exp);
    }

    pub fn reset_exp(&mut self, now: Instant) {
        self.exp_count = 1;
        self.peer_idle.reset(now)
    }

    fn calculate_periods(exp_count: u32, rtt: &Rtt) -> (Duration, Duration, Duration) {
        let ms = Duration::from_millis;

        // NAKInterval = min((RTT + 4 * RTTVar) / 2, 20000) - i.e. floor of 20ms
        let nak_rtt_period = (rtt.mean_as_duration() + 4 * rtt.variance_as_duration()) / 2;
        let nak_period = max(nak_rtt_period, ms(20));

        // 0.5s minimum, according to page 9
        // but 0.3s in reference implementation
        let exp_rtt_period = 4 * rtt.mean_as_duration() + rtt.variance_as_duration() + Self::SYN;
        let exp_period = max(exp_count * exp_rtt_period, exp_count * ms(300));

        // full ack period is always 10 ms
        (ms(10), nak_period, exp_period)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    use crate::packet::TimeSpan;

    proptest! {
        #[test]
        fn nak(simulated_rtt in 0i32..500_000) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = Rtt::default();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // above lower bound of NAK
            prop_assume!((rtt_mean + 4 * rtt_variance) / 2 > ms(20));

            let start = Instant::now();
            let mut timers = Timers::new(start, ms(10_000), ms(5_000));

            timers.update_rtt(&rtt);

            // NAKInterval = min(RTT + 4 * RTTVar / 2, 20ms) - i.e. floor 20ms
            assert_eq!(timers.nak.next_instant() - start, (rtt_mean + 4 * rtt_variance) / 2);

            // ACK is always 10ms
            assert_eq!(timers.full_ack.next_instant() - start, ms(10));
        }

        #[test]
        fn exp(simulated_rtt in 0i32..500_000) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = Rtt::default();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // above lower bound of EXP
            prop_assume!(4 * rtt_mean + rtt_variance + syn > ms(300));

            let start = Instant::now();
            let mut timers = Timers::new(start, ms(10_000), ms(5_000));

            timers.update_rtt(&rtt);

            // 4 * RTT + RTTVar + SYN
            assert_eq!(timers.exp.next_instant() - start, 4 * rtt_mean + rtt_variance + syn);

            // ACK is always 10ms
            assert_eq!(timers.full_ack.next_instant() - start, ms(10));

            // ACK is always 10ms
            assert_eq!(timers.full_ack.next_instant() - start, ms(10));
        }

        #[test]
        fn nak_lower_bound(simulated_rtt in 0i32..100_000) {
            prop_assume!(simulated_rtt >= 10_000);
            let mut rtt = Rtt::default();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // below lower bound of NAK
            prop_assume!((rtt_mean + 4 * rtt_variance) / 2 <= ms(20));

            let start = Instant::now();
            let mut timers = Timers::new(start, ms(10_000), ms(5_000));

            timers.update_rtt(&rtt);

            // NAKInterval = min(RTT + 4 * RTTVar / 2, 20ms) - i.e. floor 20ms
            assert_eq!(timers.nak.next_instant() - start, ms(20));

            // ACK is always 10ms
            assert_eq!(timers.full_ack.next_instant() - start, ms(10));
        }

        #[test]
        fn exp_lower_bound(simulated_rtt in 0i32..100_000) {
            prop_assume!(simulated_rtt >= 0);
            let mut rtt = Rtt::default();
            for _ in 0..1000 {
                rtt.update(TimeSpan::from_micros(simulated_rtt));
            }

            let ms = Duration::from_millis;
            let syn = ms(10);
            let rtt_mean = rtt.mean_as_duration();
            let rtt_variance = rtt.variance_as_duration();

            // below lower bound of EXP
            prop_assume!(4 * rtt_mean + rtt_variance + syn <= ms(300));

            let start = Instant::now();
            let mut timers = Timers::new(start, ms(10_000), ms(5_000));

            timers.update_rtt(&rtt);

            // exp has a lower bound period of 300ms
            assert_eq!(timers.exp.next_instant() - start, ms(300));

            // ACK is always 10ms
            assert_eq!(timers.full_ack.next_instant() - start, ms(10));
        }
    }

    #[test]
    fn next_timer() {
        let ms = TimeSpan::from_millis;
        let start = Instant::now();
        let mut timers = Timers::new(start, Duration::MAX, Duration::from_millis(5_000));

        // next timer should be ack, 10ms
        let now = start;
        let actual_timer = timers.next_timer(now, false, None, 1);
        assert_eq!(TimeSpan::from_interval(now, actual_timer), ms(10));

        // ack should be disabled if there are no packets waiting acknowledgement
        let actual_timer = timers.next_timer(now, false, None, 0);
        assert!(TimeSpan::from_interval(now, actual_timer) > ms(10));

        // fast forward the clock, ACK will fire before other timers
        let now = start + ms(15);
        // only ACK timer should fire
        assert!(timers.check_full_ack(now).is_some());
        assert!(timers.check_nak(now).is_none());
        assert!(timers.check_peer_idle_timeout(now).is_none());

        // NAK will have a lower bound period of 20ms
        let nak = ms(20);
        let actual_timer = timers.next_timer(now, false, Some(start + ms(10_000)), 1);
        assert_eq!(TimeSpan::from_interval(start, actual_timer), nak);

        // the NAK timer should trigger
        assert!(timers.check_full_ack(actual_timer).is_some());
        assert!(timers.check_nak(actual_timer).is_some());
        assert!(timers.check_peer_idle_timeout(actual_timer).is_none());

        // EXP will have a lower bound period of 300ms
        let exp_lower_bound = ms(300);
        let now = start + exp_lower_bound;

        // push time forward for ACK and NAK first
        assert!(timers.check_full_ack(now).is_some());
        assert!(timers.check_nak(now).is_some());

        // next timer should be EXP
        let actual_timer = timers.next_timer(now, false, Some(start + ms(10_000)), 1);
        assert_eq!(
            TimeSpan::from_interval(start, actual_timer),
            exp_lower_bound
        );

        // EXP timer should trigger
        assert!(timers.check_full_ack(actual_timer).is_none());
        assert!(timers.check_nak(actual_timer).is_none());
        let last_input = start;
        timers.reset_exp(last_input);
        for exp_count in 1..=16 {
            assert!(timers
                .check_peer_idle_timeout(last_input + exp_count * exp_lower_bound)
                .is_none());
        }
        assert!(timers
            .check_peer_idle_timeout(last_input + 17 * exp_lower_bound)
            .is_some());
    }
}
