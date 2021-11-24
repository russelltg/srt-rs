// lossy tests based on protocol to be fully deterministic

use std::cmp::min;
use std::collections::VecDeque;
use std::{
    str,
    time::{Duration, Instant},
};

use log::{info, trace};
use rand::distributions::Bernoulli;
use rand::{prelude::StdRng, SeedableRng};
use srt_protocol::connection::Input;

pub mod simulator;

use rand_distr::Normal;
use simulator::*;

#[test]
fn lossy_deterministic() {
    let _ = pretty_env_logger::try_init();

    let once_failing_seeds = [
        (13858442656353620955, 10_000),
        (3330590297113083014, 10_000),
        (11174431011217123256, 10_000),
        (7843866891970470107, 10_000),
        (940980453060602806, 10_000),
        (10550053401338237831, 10_000),
        (9602806002654919948, 10_000),
        (11134687271549837280, 10_000),
        (10210281456068034833, 10_000),
    ];
    for &(s, size) in &once_failing_seeds {
        do_lossy_test(s, size);
    }

    for _ in 0..10 {
        let seed = rand::random();
        do_lossy_test(seed, 10_000);
    }
}

fn do_lossy_test(seed: u64, count: usize) {
    info!("Seed is: {}, count is: {}", seed, count);

    const PACKET_SPACING: Duration = Duration::from_millis(1);
    const DROP_RATE: f64 = 0.06;
    let delay_mean = Duration::from_secs_f64(20e-3);
    let delay_stdev = Duration::from_secs_f64(4e-3);

    let start = Instant::now();

    let mut simulation = RandomLossSimulation {
        rng: StdRng::seed_from_u64(seed),
        delay_dist: Normal::new(delay_mean.as_secs_f64(), delay_stdev.as_secs_f64()).unwrap(),
        drop_dist: Bernoulli::new(DROP_RATE).unwrap(),
    };
    let (mut network, mut sender, mut receiver) = simulation.build(start, Duration::from_secs(1));
    input_data_simulation(start, count, PACKET_SPACING, &mut network.sender);

    let mut now = start;
    let mut next_data = 0i32;
    let mut dropped = 0i32;
    let mut received = 0i32;
    loop {
        let sender_next_time = if sender.is_open() {
            assert_eq!(sender.next_data(now), None);

            while let Some(packet) = sender.next_packet(now) {
                match simulation.next_packet_schedule(now) {
                    Some(release_at) => network.send(release_at, packet),
                    None => trace!("Dropping {:?}", packet),
                }
            }

            let next_timer = sender.check_timers(now);
            let (next_time, input) = network.sender.select_next_input(now, next_timer);
            match input {
                Input::Data(data) => sender.handle_data_input(next_time, data),
                Input::Packet(packet) => sender.handle_packet_input(next_time, packet),
                _ => {}
            };
            Some(next_time)
        } else {
            None
        };

        let receiver_next_time = if receiver.is_open() {
            while let Some((ts, payload)) = receiver.next_data(now) {
                let diff_ms = (now - ts).as_millis();
                assert!(
                    700 < diff_ms && diff_ms < 1300,
                    "Latency not in tolerance zone: {}ms",
                    diff_ms
                );

                let actual: i32 = str::from_utf8(&payload[..]).unwrap().parse().unwrap();
                dropped += actual - next_data;
                next_data = actual + 1;
                received += 1;
            }

            while let Some(packet) = receiver.next_packet(now) {
                match simulation.next_packet_schedule(now) {
                    Some(release_at) => network.send(release_at, packet),
                    None => trace!("Dropping {:?}", packet),
                }
            }

            let next_timer = receiver.check_timers(now);
            let (next_time, input) = network.receiver.select_next_input(now, next_timer);
            match input {
                Input::Data(data) => receiver.handle_data_input(now, data),
                Input::Packet(packet) => receiver.handle_packet_input(now, packet),
                _ => {}
            };
            Some(next_time)
        } else {
            None
        };

        let next_time = match (sender_next_time, receiver_next_time) {
            (Some(s), Some(r)) => min(s, r),
            (Some(s), None) => s,
            (None, Some(r)) => r,
            _ => break,
        };

        let delta = next_time - now;
        trace!("Delta = {:?}", delta);
        now = next_time;
    }

    info!("Received: {}", received);

    assert_ne!(received, 0);
    assert!(dropped < 15, "Expected less than 15 drops, got {}", dropped);
}

#[test]
fn high_bandwidth_deterministic() {
    do_high_bandwidth_deterministic(rand::random(), 100_000);
}

fn do_high_bandwidth_deterministic(seed: u64, count: usize) {
    let start = Instant::now();

    let delay_mean = Duration::from_millis(10);
    let delay_stdev = Duration::from_millis(1);
    let drop_rate = 0.005;

    let bandwidth_mbps = 50.; // MB/second
    let packet_size = 1316; // bytes/packet. Note that packets are not actually this large, but packet size does not affect non-realtime tests like this
    let packet_spacing =
        Duration::from_secs_f64(f64::from(packet_size) / bandwidth_mbps / (1024. * 1024.)); // s/packet

    let mut simulation = RandomLossSimulation {
        rng: StdRng::seed_from_u64(seed),
        delay_dist: Normal::new(delay_mean.as_secs_f64(), delay_stdev.as_secs_f64()).unwrap(),
        drop_dist: Bernoulli::new(drop_rate).unwrap(),
    };
    let (mut network, mut sender, mut receiver) = simulation.build(start, Duration::from_secs(1));
    input_data_simulation(start, count, packet_spacing, &mut network.sender);

    let mut now = start;

    let window_size = Duration::from_secs(1);
    let startup_packets = 1_000;

    let mut window = VecDeque::new();
    let mut bytes_received = 0;
    let mut packets_received = 0;
    loop {
        let sender_next_time = if sender.is_open() {
            assert_eq!(sender.next_data(now), None);

            while let Some(packet) = sender.next_packet(now) {
                match simulation.next_packet_schedule(now) {
                    Some(release_at) => network.send(release_at, packet),
                    None => trace!("Dropping {:?}", packet),
                }
            }

            let next_timer = sender.check_timers(now);
            let (next_time, input) = network.sender.select_next_input(now, next_timer);
            match input {
                Input::Data(data) => sender.handle_data_input(next_time, data),
                Input::Packet(packet) => sender.handle_packet_input(next_time, packet),
                _ => {}
            };
            Some(next_time)
        } else {
            None
        };

        let receiver_next_time = if receiver.is_open() {
            while let Some((ts, _payload)) = receiver.next_data(now) {
                bytes_received += packet_size;
                window.push_back((ts, packet_size));
                packets_received += 1;

                while let Some((a, bytes)) = window.front() {
                    if ts - *a > window_size {
                        bytes_received -= *bytes;
                        window.pop_front();
                    } else {
                        break;
                    }
                }

                let rate_mbps = bytes_received as f64 / 1024. / 1024.;

                // TODO: uncomment this
                // if packets_received >= startup_packets {
                //     assert!(
                //         rate_mbps > bandwidth_mbps * 0.9,
                //         "Rate was {}, expected at least {}",
                //         rate_mbps,
                //         bandwidth_mbps * 0.9
                //     );
                //     assert!(
                //         rate_mbps > bandwidth_mbps * 1.1,
                //         "Rate was {}, expecte less than {}",
                //         rate_mbps,
                //         bandwidth_mbps * 1.1
                //     );
                // }

                print!("Received {:10.3}MB/s\r", rate_mbps);
            }

            while let Some(packet) = receiver.next_packet(now) {
                match simulation.next_packet_schedule(now) {
                    Some(release_at) => network.send(release_at, packet),
                    None => trace!("Dropping {:?}", packet),
                }
            }

            let next_timer = receiver.check_timers(now);
            let (next_time, input) = network.receiver.select_next_input(now, next_timer);
            match input {
                Input::Data(data) => receiver.handle_data_input(now, data),
                Input::Packet(packet) => receiver.handle_packet_input(now, packet),
                _ => {}
            };
            Some(next_time)
        } else {
            None
        };

        let next_time = match (sender_next_time, receiver_next_time) {
            (Some(s), Some(r)) => min(s, r),
            (Some(s), None) => s,
            (None, Some(r)) => r,
            _ => break,
        };

        let delta = next_time - now;
        trace!("Delta = {:?}", delta);
        now = next_time;
    }

    assert_eq!(packets_received, count);
}
