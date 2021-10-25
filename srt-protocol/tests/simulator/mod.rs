use log::{error, warn};
use rand::distributions::Bernoulli;
use rand::prelude::*;
use rand_distr::Normal;
use srt_protocol::connection::{DuplexConnection, Input};
use srt_protocol::protocol::handshake::Handshake;
use srt_protocol::{Connection, ConnectionSettings, LiveBandwidthMode, Packet};
use std::{
    cmp::max,
    collections::BinaryHeap,
    convert::TryFrom,
    net::SocketAddr,
    time::{Duration, Instant},
};

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

pub fn input_data_simulation(
    start: Instant,
    count: usize,
    pace: Duration,
    peer: &mut PeerSimulator,
) {
    let count = u32::try_from(count).unwrap();
    for i in 1..=count {
        let t = start + pace * i;
        peer.schedule_input(t, Input::Data(Some((t, i.to_string().into()))));
    }
    peer.schedule_input(start + pace * (count + 1), Input::Data(None));
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
        self.input.push(ScheduledInput(release_at, input));
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
            self.sender.schedule_input(
                release_at,
                Input::Packet(Some((packet, self.receiver.addr()))),
            );
        } else if to == self.receiver.addr() {
            self.receiver.schedule_input(
                release_at,
                Input::Packet(Some((packet, self.sender.addr()))),
            );
        } else {
            error!("Dropping {:?}", packet)
        }
    }

    pub fn send_lossy(
        &mut self,
        sim: &mut RandomLossSimulation,
        now: Instant,
        packet: (Packet, SocketAddr),
    ) {
        self.send(
            match sim.next_packet_schedule(now) {
                Some(time) => time,
                None => {
                    warn!("Dropping {:?} to {}", packet.0, packet.1);
                    return;
                }
            },
            packet,
        )
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
        latency: Duration,
    ) -> (NetworkSimulator, DuplexConnection, DuplexConnection) {
        let sender = self.new_connection_settings(start, latency);
        let receiver = ConnectionSettings {
            remote: (sender.remote.ip(), sender.remote.port() + 1).into(),
            remote_sockid: sender.local_sockid,
            local_sockid: sender.remote_sockid,
            init_seq_num: sender.init_seq_num,
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
            Some(now + Duration::from_secs_f64(self.delay_dist.sample(&mut self.rng).abs()))
        } else {
            None
        }
    }

    fn new_connection_settings(&mut self, start: Instant, latency: Duration) -> ConnectionSettings {
        ConnectionSettings {
            remote: ([127, 0, 0, 1], self.rng.gen()).into(),
            remote_sockid: self.rng.gen(),
            local_sockid: self.rng.gen(),
            socket_start_time: start,
            rtt: Duration::default(),
            init_seq_num: self.rng.gen(),
            max_packet_size: 1316,
            max_flow_size: 8192,
            send_tsbpd_latency: latency,
            recv_tsbpd_latency: latency,
            crypto_manager: None,
            stream_id: None,
            bandwidth: LiveBandwidthMode::default(),
            recv_buffer_size: 8192,
        }
    }
}
