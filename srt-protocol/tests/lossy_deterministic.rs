// lossy tests based on protocol to be fully deterministic

use bytes::Bytes;
use log::trace;
use lossy_conn::SyncLossyConn;
use rand::{prelude::StdRng, Rng, SeedableRng};
use srt_protocol::{
    protocol::{
        handshake::Handshake,
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    ConnectionSettings,
};
use std::{
    convert::identity,
    str,
    time::{Duration, Instant},
};

mod lossy_conn;

#[test]
fn lossy_deterministic() {
    let _ = pretty_env_logger::try_init();

    let once_failing_seeds = [
        (7843866891970470107, 10),
        (940980453060602806, 10_000),
        (10550053401338237831, 10_000),
        (9602806002654919948, 10),
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
    println!("Seed is: {}", seed);
    let start = Instant::now();
    let mut rng = StdRng::seed_from_u64(seed);

    let s1 = ConnectionSettings {
        remote: ([127, 0, 0, 1], 2222).into(),
        remote_sockid: rng.gen(),
        local_sockid: rng.gen(),
        socket_start_time: start,
        init_send_seq_num: rng.gen(),
        init_recv_seq_num: rng.gen(),
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_secs(8),
        recv_tsbpd_latency: Duration::from_secs(8),
        crypto_manager: None,
        stream_id: None,
    };

    let s2 = ConnectionSettings {
        remote: ([127, 0, 0, 1], 2223).into(),
        remote_sockid: s1.local_sockid,
        local_sockid: s1.remote_sockid,
        socket_start_time: start,
        init_send_seq_num: s1.init_recv_seq_num,
        init_recv_seq_num: s1.init_send_seq_num,
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_secs(8),
        recv_tsbpd_latency: Duration::from_secs(8),
        crypto_manager: None,
        stream_id: None,
    };

    let mut sendr = Sender::new(s1, Handshake::Connector);
    let mut recvr = Receiver::new(s2, Handshake::Connector);

    const PACKET_SPACING: Duration = Duration::from_millis(10);
    const DROP_RATE: f64 = 0.06;
    let delay_mean = Duration::from_secs_f64(20e-3);
    let delay_stdev = Duration::from_secs_f64(4e-3);

    let mut conn = SyncLossyConn::new(delay_mean, delay_stdev, DROP_RATE, rng);

    let mut current_time = start;

    let mut next_send_time = Some(current_time);
    let mut next_packet_id = 0;

    let mut dropped = 0;
    let mut next_data = 0;

    loop {
        if Some(current_time) == next_send_time {
            sendr.handle_data(
                (current_time, Bytes::from(next_packet_id.to_string())),
                current_time,
            );

            next_packet_id += 1;
            if next_packet_id == count {
                next_send_time = None;
                sendr.handle_close();
            } else {
                next_send_time = Some(current_time + PACKET_SPACING);
            }
        }

        let conn_next_time = loop {
            match conn.action(current_time) {
                lossy_conn::Action::Wait(until) => break until,
                lossy_conn::Action::S2R(pack) => {
                    trace!("s->r {:?}", pack);
                    recvr.handle_packet(current_time, (pack, ([127, 0, 0, 1], 2223).into()));
                }
                lossy_conn::Action::R2S(pack) => {
                    trace!("r->s {:?}", pack);
                    sendr.handle_packet((pack, ([127, 0, 0, 1], 2222).into()), current_time)
                }
            }
        };

        let sender_next_time = match sendr.next_action(current_time) {
            SenderAlgorithmAction::WaitUntilAck | SenderAlgorithmAction::WaitForData => None,
            SenderAlgorithmAction::WaitUntil(time) => Some(time),
            SenderAlgorithmAction::Close => None, // xxx
        };
        while let Some((packet, _)) = sendr.pop_output() {
            conn.push_s2r(packet, current_time);
        }

        let receiver_next_time = loop {
            match recvr.next_algorithm_action(current_time) {
                ReceiverAlgorithmAction::TimeBoundedReceive(time) => break Some(time),
                ReceiverAlgorithmAction::SendControl(cp, _) => {
                    conn.push_r2s(cp.into(), current_time);
                }
                ReceiverAlgorithmAction::OutputData((ts, payload)) => {
                    let diff_ms = (current_time - ts).as_millis();

                    assert!(
                        7900 < diff_ms && diff_ms < 8700,
                        "Latency not in tolerance zone: {}ms",
                        diff_ms
                    );

                    let actual: i32 = str::from_utf8(&payload[..]).unwrap().parse().unwrap();
                    dropped += actual - next_data;

                    next_data = actual + 1;
                } // xxx
                ReceiverAlgorithmAction::Close => break None,
            }
        };

        // determine if we are done or not
        if recvr.is_flushed() && sendr.is_flushed() && next_packet_id == count {
            break;
        }

        // use the next smallest one
        let new_current = [
            next_send_time,
            sender_next_time,
            receiver_next_time,
            conn_next_time,
        ]
        .iter()
        .copied()
        .filter_map(identity)
        .min()
        .unwrap();

        if next_send_time == Some(new_current) {
            trace!("Waking up to give data to sender");
        }
        if sender_next_time == Some(new_current) {
            trace!("Waking up from sender")
        }
        if receiver_next_time == Some(new_current) {
            trace!("Waking up from receiver")
        }
        if conn.next_release_time() == Some(new_current) {
            trace!("Waking up for connection")
        }

        let delta = new_current - current_time;
        current_time = new_current;

        trace!("Delta = {:?}", delta);
    }
    assert!(dropped < 15, "Expected less than 15 drops, got {}", dropped);
}
