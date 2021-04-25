use std::time::{Duration, Instant};

use bytes::Bytes;
use log::{info, trace};
use srt_protocol::{
    packet::ControlTypes,
    protocol::{
        handshake::Handshake,
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    ConnectionSettings, ControlPacket, SeqNumber, SocketId,
};

const DATA: [u8; 1024] = [5; 1024];

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
        init_send_seq_num: init_seqnum,
        init_recv_seq_num: init_seqnum,
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
    };

    let s2 = ConnectionSettings {
        remote: s1_addr,
        remote_sockid: s1_sockid,
        local_sockid: s2_sockid,
        socket_start_time: start,
        rtt: Duration::default(),
        init_send_seq_num: init_seqnum,
        init_recv_seq_num: init_seqnum,
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
    };

    let mut sendr = Sender::new(s1, Handshake::Connector);
    let mut recvr = Receiver::new(s2, Handshake::Connector);

    // send 10 packet/s for 24 hours
    const PACKET_RATE: u32 = 10;
    let packs_to_send = 60 * 60 * 24 * PACKET_RATE;
    let mut send_time = (1..=packs_to_send)
        .map(|i| (i, start + i * Duration::from_secs(1) / PACKET_RATE))
        .peekable();

    let mut current_time = start;
    let mut recvd_packets = 0;
    let mut last_ts = 0;

    loop {
        if let Some((idx, rel_time)) = send_time.peek() {
            if *rel_time <= current_time {
                sendr.handle_data((current_time, Bytes::from_static(&DATA)), current_time);

                if idx % (60 * 20) == 0 {
                    info!(
                        "{}h{}m passed",
                        idx / 60 / 60 / PACKET_RATE,
                        (idx / 60 / PACKET_RATE) % 60
                    );
                }

                send_time.next();

                if send_time.peek().is_none() {
                    sendr.handle_close();
                }
            }
        }

        let sender_next_time = match sendr.next_action(current_time) {
            SenderAlgorithmAction::WaitUntilAck | SenderAlgorithmAction::WaitForData => None,
            SenderAlgorithmAction::WaitUntil(time) => Some(time),
            SenderAlgorithmAction::Close => None, // xxx
        };

        while let Some((packet, _)) = sendr.pop_output() {
            if matches!(
                packet.control(),
                Some(ControlPacket {
                    control_type: ControlTypes::Shutdown,
                    ..
                })
            ) {
                info!("shutdown");
            }

            let ts = packet.timestamp().as_micros();
            if ts < last_ts {
                info!("rollover packs={}", recvd_packets);
            }
            last_ts = ts;

            recvr.handle_packet(current_time, (packet, s1_addr));
        }

        trace!("s={:?} r={:?}", sendr, recvr);

        let receiver_next_time = loop {
            match recvr.next_algorithm_action(current_time) {
                ReceiverAlgorithmAction::TimeBoundedReceive(time) => break Some(time),
                ReceiverAlgorithmAction::SendControl(cp, _) => {
                    sendr.handle_packet((cp.into(), s2_addr), current_time);
                }
                ReceiverAlgorithmAction::OutputData(_) => {
                    recvd_packets += 1;
                } // xxx
                ReceiverAlgorithmAction::Close => break None,
            }
        };

        // determine if we are done or not
        if recvr.is_flushed() && sendr.is_flushed() && send_time.peek().is_none() {
            break;
        }

        // use the next smallest one
        let new_current = [
            send_time.peek().map(|(_, time)| *time),
            sender_next_time,
            receiver_next_time,
        ]
        .iter()
        .copied()
        .flatten()
        .min()
        .unwrap();

        if send_time.peek().map(|(_, time)| *time) == Some(new_current) {
            trace!("Waking up to give data to sender");
        }
        if sender_next_time == Some(new_current) {
            trace!("Waking up from sender")
        }
        if receiver_next_time == Some(new_current) {
            trace!("Waking up from receiver")
        }

        let delta = new_current - current_time;
        current_time = new_current;

        trace!("Delta = {:?}", delta);
    }

    assert_eq!(packs_to_send, recvd_packets);
}
