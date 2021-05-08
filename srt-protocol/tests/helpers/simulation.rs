use srt_protocol::connection::{Input, DuplexConnection};
use srt_protocol::{Packet, ConnectionSettings, Connection};
use bytes::Bytes;
use log::error;
use std::{
    cmp::max,
    collections::BinaryHeap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use rand::prelude::*;
use rand_distr::Normal;
use srt_protocol::protocol::handshake::Handshake;
use rand::distributions::Bernoulli;

#[derive(Eq, PartialEq)]
struct SentPacket(Instant, (Packet, SocketAddr));

impl PartialOrd for SentPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0).reverse()) // reverse to make it a min-heap
    }
}

impl Ord for SentPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Eq, PartialEq)]
struct ScheduledInput(Instant, Input);

impl PartialOrd for ScheduledInput {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0).reverse()) // reverse to make it a min-heap
    }
}

impl Ord for ScheduledInput {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

pub struct InputDataSimulation {
    count: usize,
    pace: Duration,
    next_send_time: Option<Instant>,
    next_packet_id: usize,
}

impl InputDataSimulation {
    pub fn new(start: Instant, count: usize, pace: Duration) -> InputDataSimulation {
        InputDataSimulation {
            count,
            pace,
            next_send_time: Some(start + pace),
            next_packet_id: 0,
        }
    }

    pub fn send_data_to(&mut self, now: Instant, peer: &mut PeerSimulator) {
        while let Some(time) = self.next_send_time {
            if time > now {
                break;
            }

            if self.next_packet_id < self.count {
                self.next_send_time = Some(time + self.pace);
                self.next_packet_id += 1;
                let data = Bytes::from(self.next_packet_id.to_string());
                peer.schedule_input(now, Input::Data(Some((now, data))));
            } else {
                self.next_send_time = None;
                peer.schedule_input(now, Input::Data(None));
            }
        }
    }
}

pub struct PeerSimulator {
    addr: SocketAddr,
    input: BinaryHeap<ScheduledInput>,
}

impl PeerSimulator {
    pub fn new(addr: SocketAddr) -> PeerSimulator {
        PeerSimulator {
            addr,
            input: BinaryHeap::new(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn schedule_input(&mut self, release_at: Instant, input: Input) {
        self.input
            .push(ScheduledInput(release_at, input));
    }

    pub fn select_next_input(&mut self, now: Instant, next_timer: Instant) -> (Instant, Input) {
        if self.has_scheduled_input(next_timer) {
            self.input.pop().map(|i| (max(now, i.0), i.1)).unwrap()
        } else {
            (next_timer, Input::Timer)
        }
    }

    fn has_scheduled_input(&self, now: Instant) -> bool {
        self.input
            .peek()
            .map(|i| i.0)
            .filter(|t| *t <= now)
            .is_some()
    }
}

pub struct NetworkSimulator {
    pub sender: PeerSimulator,
    pub receiver: PeerSimulator,
}

impl NetworkSimulator {
    pub fn new(sender_addr: SocketAddr, receiver_addr: SocketAddr) -> NetworkSimulator {
        NetworkSimulator {
            sender: PeerSimulator::new(sender_addr),
            receiver: PeerSimulator::new(receiver_addr),
        }
    }

    pub fn send(&mut self, release_at: Instant, (packet, to): (Packet, SocketAddr)) {
        if to == self.sender.addr() {
            self.sender
                .schedule_input(release_at, Input::Packet(Some((packet, self.receiver.addr()))));
        } else if to == self.receiver.addr() {
            self.receiver
                .schedule_input(release_at, Input::Packet(Some((packet, self.sender.addr()))));
        } else {
            error!("Dropping {:?}", packet)
        }
    }
}

pub struct RandomLossSimulation {
    pub rng: StdRng,
    pub delay_dist: Normal<f64>,
    pub drop_dist: Bernoulli,
}

impl RandomLossSimulation {
    pub fn build(
        &mut self,
        start: Instant,
    ) -> (NetworkSimulator, DuplexConnection, DuplexConnection) {
        let sender = self.new_connection_settings(start);
        let receiver = ConnectionSettings {
            remote: (sender.remote.ip(), sender.remote.port() + 1).into(),
            remote_sockid: sender.local_sockid,
            local_sockid: sender.remote_sockid,
            init_send_seq_num: sender.init_recv_seq_num,
            init_recv_seq_num: sender.init_send_seq_num,
            ..sender.clone()
        };

        let network = NetworkSimulator::new(receiver.remote, sender.remote);
        let sender = DuplexConnection::new(Connection {
            settings: sender,
            handshake: Handshake::Connector,
        });
        let receiver = DuplexConnection::new(Connection {
            settings: receiver,
            handshake: Handshake::Connector,
        });

        (network, sender, receiver)
    }

    pub fn next_packet_schedule(&mut self, now: Instant) -> Option<Instant> {
        if !self.drop_dist.sample(&mut self.rng) {
            Some(
                now + Duration::from_secs_f64(
                    self.delay_dist.sample(&mut self.rng).abs() / 10.0,
                ),
            )
        } else {
            None
        }
    }

    fn new_connection_settings(&mut self, start: Instant) -> ConnectionSettings {
        ConnectionSettings {
            remote: ([127, 0, 0, 1], self.rng.gen()).into(),
            remote_sockid: self.rng.gen(),
            local_sockid: self.rng.gen(),
            socket_start_time: start,
            rtt: Duration::default(),
            init_send_seq_num: self.rng.gen(),
            init_recv_seq_num: self.rng.gen(),
            max_packet_size: 1316,
            max_flow_size: 8192,
            send_tsbpd_latency: Duration::from_millis(1000),
            recv_tsbpd_latency: Duration::from_millis(1000),
            crypto_manager: None,
            stream_id: None,
        }
    }
}
