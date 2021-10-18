use log::{info, trace};
use rand::{prelude::StdRng, SeedableRng};
use rand_distr::{Bernoulli, Normal};
use srt_protocol::connection::Input;
use std::{
    cmp::min,
    str,
    time::{Duration, Instant},
};

pub mod simulator;

use simulator::*;

#[test]
fn not_enough_latency() {
    // once failing seeds
    do_not_enough_latency(6785379667375872404);

    for _ in 0..100 {
        do_not_enough_latency(rand::random());
    }
}

fn do_not_enough_latency(seed: u64) {
    println!("not_enough_latency seed is {}", seed);

    let _ = pretty_env_logger::try_init();

    const PACKETS: usize = 1_000;
    const PACKET_SPACING: Duration = Duration::from_millis(10);

    let start = Instant::now();

    let rng = StdRng::seed_from_u64(seed);

    // 4% packet loss, 4 sec latency with 0.2 s variance
    let mut simulation = RandomLossSimulation {
        rng,
        delay_dist: Normal::new(1.5, 0.2).unwrap(),
        drop_dist: Bernoulli::new(0.01).unwrap(),
    };

    let (mut network, mut sender, mut receiver) = simulation.build(start, Duration::from_secs(2));

    let mut input_data = InputDataSimulation::new(start, PACKETS, PACKET_SPACING);

    let mut now = start;
    let mut total_recvd = 0;
    let mut total_dropped = 0;
    let mut last_data = 0;

    loop {
        let sender_next_time = if sender.is_open() {
            input_data.send_data_to(now, &mut network.sender);

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
            while let Some((_, by)) = receiver.next_data(now) {
                total_recvd += 1;

                let id = str::from_utf8(&by).unwrap().parse().unwrap();

                assert!(id > last_data, "Received {} after {}", id, last_data);

                if last_data + 1 != id {
                    info!("Packets [{}, {}) dropped", last_data + 1, id);
                    total_dropped += id - (last_data + 1);
                }
                last_data = id;
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

    assert_eq!(total_dropped + total_recvd + (1000 - last_data), 1000);
    assert!(
        total_recvd > PACKETS * 2 / 3,
        "received {} packtes, expected {}",
        total_recvd,
        PACKETS * 2 / 3
    );
    assert!(
        total_recvd < PACKETS,
        "received all ({}) packets, expected < {}",
        total_recvd,
        PACKETS
    );
}
