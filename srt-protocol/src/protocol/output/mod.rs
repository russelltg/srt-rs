use std::{collections::VecDeque, time::Instant};

use crate::{connection::ConnectionSettings, packet::*, protocol::time::TimeBase};

#[derive(Debug)]
pub struct Output {
    remote_sockid: SocketId,
    time_base: TimeBase,
    packets: VecDeque<Packet>,
}

impl Output {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_sockid: settings.remote_sockid,
            time_base: TimeBase::new(settings.socket_start_time),
            packets: VecDeque::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn send_control(&mut self, now: Instant, control: ControlTypes) {
        self.packets.push_back(Packet::Control(ControlPacket {
            timestamp: self.time_base.timestamp_from(now),
            dest_sockid: self.remote_sockid,
            control_type: control,
        }));
    }

    pub fn send_data(&mut self, _now: Instant, data: DataPacket) {
        self.packets.push_back(Packet::Data(data));
    }

    pub fn pop_packet(&mut self) -> Option<Packet> {
        self.packets.pop_front()
    }
}
