use crate::packet::ControlTypes;
use crate::packet::ControlTypes::KeepAlive;
use crate::protocol::{TimeBase, Timer};
use crate::{ConnectionSettings, ControlPacket, DataPacket, Packet, SocketId};
use std::cmp::max;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Output {
    remote_sockid: SocketId,
    time_base: TimeBase,
    packets: VecDeque<Packet>,
    // this isn't in the spec, but it's in the reference implementation
    // https://github.com/Haivision/srt/blob/1d7b391905d7e344d80b86b39ac5c90fda8764a9/srtcore/core.cpp#L10610-L10614
    keepalive_timer: Timer,
}

impl Output {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_sockid: settings.remote_sockid,
            time_base: TimeBase::new(settings.socket_start_time),
            keepalive_timer: Timer::new(Duration::from_secs(1), settings.socket_start_time),
            packets: VecDeque::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        max(now, self.keepalive_timer.next_instant())
    }

    pub fn check_timers(&mut self, now: Instant) {
        if self.keepalive_timer.check_expired(now).is_some() {
            self.send_control(now, KeepAlive);
        }
    }

    pub fn send_control(&mut self, now: Instant, control: ControlTypes) {
        self.keepalive_timer.reset(now);
        self.packets.push_back(Packet::Control(ControlPacket {
            timestamp: self.time_base.timestamp_from(now),
            dest_sockid: self.remote_sockid,
            control_type: control,
        }));
    }

    pub fn send_data(&mut self, now: Instant, p: DataPacket) {
        self.keepalive_timer.reset(now);
        self.packets.push_back(Packet::Data(p));
    }

    pub fn pop_packet(&mut self) -> Option<Packet> {
        self.packets.pop_front()
    }
}
