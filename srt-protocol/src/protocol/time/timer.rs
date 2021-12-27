use core::u32;
use std::cmp::max;
use std::time::{Duration, Instant};

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

    pub fn new(now: Instant, period: Duration) -> Timer {
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

    pub fn check_expired(&mut self, now: Instant) -> Option<u32> {
        if self.period.as_nanos() == 0 {
            return Some(1);
        }
        if now >= self.next_instant() {
            let elapsed = now - self.last;
            let elapsed_periods = (elapsed.as_nanos() / self.period.as_nanos()) as u32;
            self.last += self.period * elapsed_periods;
            Some(elapsed_periods)
        } else {
            None
        }
    }
}
