use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::{
    connection::ConnectionSettings,
    packet::*,
    protocol::time::{TimeBase, Timer},
};

#[derive(Debug)]
pub struct Output {
    remote_sockid: SocketId,
    time_base: TimeBase,
    packets: VecDeque<Packet>,
    keepalive: Timer,
}

impl Output {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_sockid: settings.remote_sockid,
            time_base: TimeBase::new(settings.socket_start_time),
            packets: VecDeque::new(),
            keepalive: Timer::new(settings.socket_start_time, Duration::from_secs(1)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn send_control(&mut self, now: Instant, control: ControlTypes) {
        self.keepalive.reset(now);
        self.packets.push_back(Packet::Control(ControlPacket {
            timestamp: self.time_base.timestamp_from(now),
            dest_sockid: self.remote_sockid,
            control_type: control,
        }));
    }

    pub fn send_data(&mut self, now: Instant, data: DataPacket) {
        self.keepalive.reset(now);
        self.packets.push_back(Packet::Data(data));
    }

    pub fn ensure_alive(&mut self, now: Instant) {
        if self.keepalive.check_expired(now).is_some() {
            self.send_control(now, ControlTypes::KeepAlive)
        }
    }

    pub fn pop_packet(&mut self) -> Option<Packet> {
        self.packets.pop_front()
    }
}
