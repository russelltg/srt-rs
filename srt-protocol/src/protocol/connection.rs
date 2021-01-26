use crate::connection::ConnectionSettings;
use crate::protocol::Timer;

use std::cmp::min;
use std::time::{Duration, Instant};

use log::info;

/// Handing connection timeout, etc
/// The only events that this entity cares about is when packets are recevied from the remote,
/// and when packets are sent from the remote
pub struct Connection {
    exp_count: u32,
    exp_timer: Timer,

    // this isn't in the spec, but it's in the reference implementation
    // https://github.com/Haivision/srt/blob/1d7b391905d7e344d80b86b39ac5c90fda8764a9/srtcore/core.cpp#L10610-L10614
    keepalive_timer: Timer,
}

pub enum ConnectionAction {
    ContinueUntil(Instant),
    SendKeepAlive,
    Close, // due to timeout
}

impl Connection {
    pub fn new(conn: ConnectionSettings) -> Self {
        Self {
            exp_count: 1,
            exp_timer: Timer::new(Duration::from_millis(500), conn.socket_start_time),
            // 1s period https://github.com/Haivision/srt/blob/1d7b391905d7e344d80b86b39ac5c90fda8764a9/srtcore/core.h#L647
            keepalive_timer: Timer::new(Duration::from_secs(1), conn.socket_start_time),
        }
    }
    pub fn on_packet(&mut self, now: Instant) {
        self.exp_count = 1;
        self.exp_timer.reset(now);
    }
    pub fn on_send(&mut self, now: Instant) {
        self.keepalive_timer.reset(now);
    }
    pub fn next_action(&mut self, now: Instant) -> ConnectionAction {
        if let Some(exp) = self.exp_timer.check_expired(now) {
            self.exp_count += 1;
            info!("Exp event hit, exp count={}", self.exp_count);
            if self.exp_count == 16 {
                info!("16 exps, timeout!");
            }
        }
        if let Some(exp) = self.keepalive_timer.check_expired(now) {
            return ConnectionAction::SendKeepAlive;
        }
        if self.exp_count >= 16 {
            ConnectionAction::Close
        } else {
            ConnectionAction::ContinueUntil(min(
                self.exp_timer.next_instant(),
                self.keepalive_timer.next_instant(),
            ))
        }
    }
}

// 0.5s min, accordiding to page 9
// self.exp.set_period(max(
//     4 * rtt + rtt_var + self.syn.period(),
//     Duration::from_millis(500),
// ));
