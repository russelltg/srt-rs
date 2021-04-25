use std::{
    collections::BinaryHeap,
    time::{Duration, Instant},
};

use log::debug;
use rand::prelude::StdRng;
use rand_distr::{Bernoulli, Distribution, Normal};
use srt_protocol::Packet;

#[derive(Eq, PartialEq)]
enum Direction {
    S2R,
    R2S,
}

#[derive(Eq, PartialEq)]
struct HeapEntry {
    packet: Packet,
    release_at: Instant,
    direction: Direction,
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.release_at.cmp(&other.release_at).reverse()) // reverse to make it a min-heap
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}
pub struct SyncLossyConn {
    heap: BinaryHeap<HeapEntry>,
    rng: StdRng,
    delay_dist: Normal<f64>,
    drop_dist: Bernoulli,
}

pub enum Action {
    Wait(Option<Instant>),
    S2R(Packet),
    R2S(Packet),
}

impl SyncLossyConn {
    pub fn new(
        delay_avg: Duration,
        delay_std: Duration,
        drop_rate: f64,
        rng: StdRng,
    ) -> SyncLossyConn {
        SyncLossyConn {
            heap: BinaryHeap::new(),
            rng,
            delay_dist: Normal::new(delay_avg.as_secs_f64(), delay_std.as_secs_f64()).unwrap(),
            drop_dist: Bernoulli::new(drop_rate).unwrap(),
        }
    }

    pub fn push_s2r(&mut self, packet: Packet, now: Instant) {
        if self.drop_dist.sample(&mut self.rng) {
            debug!("Dropping {:?}", packet);
            return;
        }

        let release_at = now + self.get_delay();
        self.heap.push(HeapEntry {
            packet,
            release_at,
            direction: Direction::S2R,
        });
    }
    pub fn push_r2s(&mut self, packet: Packet, now: Instant) {
        if self.drop_dist.sample(&mut self.rng) {
            debug!("Dropping {:?}", packet);
            return;
        }

        let release_at = now + self.get_delay();
        self.heap.push(HeapEntry {
            packet,
            release_at,
            direction: Direction::R2S,
        });
    }

    fn get_delay(&mut self) -> Duration {
        Duration::from_secs_f64(self.delay_dist.sample(&mut self.rng).abs())
    }

    pub fn next_release_time(&self) -> Option<Instant> {
        self.heap.peek().map(|e| e.release_at)
    }

    pub fn action(&mut self, now: Instant) -> Action {
        if let Some(entry) = self.heap.peek() {
            if entry.release_at <= now {
                return match entry.direction {
                    Direction::S2R => Action::S2R(self.heap.pop().unwrap().packet),
                    Direction::R2S => Action::R2S(self.heap.pop().unwrap().packet),
                };
            }
        }

        Action::Wait(self.next_release_time())
    }
}
