use std::time::{Duration, Instant};

pub mod connection;
pub mod handshake;
pub mod receiver;
pub mod sender;

/// Timestamp in us
pub type TimeStamp = i32;

#[derive(Copy, Clone, Debug)]
pub struct TimeBase(Instant);
impl TimeBase {
    pub fn new() -> Self {
        Self(Instant::now())
    }

    pub fn from_raw(start_time: Instant) -> Self {
        Self(start_time)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn timestamp_from(&self, instant: Instant) -> TimeStamp {
        let elapsed = instant - self.0;
        elapsed.as_micros() as i32 // TODO: handle overflow here
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn instant_from(&self, timestamp: TimeStamp) -> Instant {
        self.0 + Duration::from_micros(timestamp as u64)
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
    pub fn new(period: Duration, now: Instant) -> Timer {
        Timer { period, last: now }
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
