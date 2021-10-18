use log::trace;
use srt_protocol::connection::{DuplexConnection, Input};
use srt_protocol::protocol::handshake::Handshake;
use srt_protocol::{Connection, ConnectionSettings, LiveBandwidthMode, SeqNumber, SocketId};
use std::cmp::min;
use std::time::{Duration, Instant};

pub mod simulator;

use simulator::*;

#[test]
fn timestamp_rollover() {
    let _ = pretty_env_logger::try_init();

    let s1_sockid = SocketId(1234);
    let s2_sockid = SocketId(5678);

    let s1_addr = ([127, 0, 0, 1], 2223).into();
    let s2_addr = ([127, 0, 0, 1], 2222).into();

    let init_seqnum = SeqNumber::new_truncate(91234);

    let start = Instant::now() + Duration::from_micros(u32::MAX as u64);

    let s1 = ConnectionSettings {
        remote: s2_addr,
        remote_sockid: s2_sockid,
        local_sockid: s1_sockid,
        socket_start_time: start,
        rtt: Duration::default(),
        init_seq_num: init_seqnum,
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
        bandwidth: LiveBandwidthMode::default(),
        recv_buffer_size: 8192,
    };

    let s2 = ConnectionSettings {
        remote: s1_addr,
        remote_sockid: s1_sockid,
        local_sockid: s2_sockid,
        socket_start_time: start,
        rtt: Duration::default(),
        init_seq_num: init_seqnum,
        max_packet_size: 1316,
        max_flow_size: 8192,

        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
        bandwidth: LiveBandwidthMode::default(),
        recv_buffer_size: 8192,
    };

    const PACKET_RATE: u32 = 10; // 10 packet/s
    const STREAM_DURATION: u32 = 2 * 60 * 60; // 2 hours

    let packs_to_send = STREAM_DURATION * PACKET_RATE;
    let latency = Duration::from_millis(10);

    let mut network = NetworkSimulator::new(s1_addr, s2_addr);
    let mut sender = DuplexConnection::new(Connection {
        settings: s1,
        handshake: Handshake::Connector,
    });
    let mut receiver = DuplexConnection::new(Connection {
        settings: s2,
        handshake: Handshake::Connector,
    });
    let mut input_data = InputDataSimulation::new(
        start,
        packs_to_send as usize,
        Duration::from_secs(1) / PACKET_RATE,
    );

    let mut now = start;
    let mut received = vec![];
    let mut dropped = vec![];
    let mut next_data = 1;
    loop {
        let sender_next_time = if sender.is_open() {
            input_data.send_data_to(now, &mut network.sender);

            assert_eq!(sender.next_data(now), None);

            while let Some(packet) = sender.next_packet(now) {
                network.send(now + latency, packet);
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
            while let Some((_, payload)) = receiver.next_data(now) {
                let actual: i32 = std::str::from_utf8(&payload[..]).unwrap().parse().unwrap();
                received.push(actual);
                dropped.extend(next_data..actual);
                next_data = actual + 1;
            }

            while let Some(packet) = receiver.next_packet(now) {
                network.send(now + latency, packet);
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
    assert_eq!(dropped, Vec::new());
    assert_eq!(packs_to_send as usize, received.len());
}
