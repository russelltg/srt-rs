use std::{
    collections::VecDeque,
    convert::identity,
    iter::repeat,
    time::{Duration, Instant},
};

use bytes::Bytes;
use log::{debug, info, trace};
use rand::{prelude::StdRng, Rng, SeedableRng};
use srt_protocol::{
    protocol::{
        handshake::Handshake,
        receiver::{Receiver, ReceiverAlgorithmAction},
        sender::{Sender, SenderAlgorithmAction},
    },
    ConnectionSettings, SeqNumber, SocketID,
};

#[test]
fn high_bandwidth_det() {
    let _ = pretty_env_logger::try_init();

    let start = Instant::now();

    let sender_addr = ([127, 0, 0, 1], 2223).into();
    let receiver_addr = ([127, 0, 0, 1], 2222).into();

    let s1 = ConnectionSettings {
        remote: receiver_addr,
        remote_sockid: SocketID(1234),
        local_sockid: SocketID(5678),
        socket_start_time: start,
        init_send_seq_num: SeqNumber::new_truncate(1234),
        init_recv_seq_num: SeqNumber::new_truncate(1234),
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
    };

    let s2 = ConnectionSettings {
        remote: sender_addr,
        remote_sockid: s1.local_sockid,
        local_sockid: s1.remote_sockid,
        socket_start_time: start,
        init_send_seq_num: s1.init_recv_seq_num,
        init_recv_seq_num: s1.init_send_seq_num,
        max_packet_size: 1316,
        max_flow_size: 8192,
        send_tsbpd_latency: Duration::from_millis(20),
        recv_tsbpd_latency: Duration::from_millis(20),
        crypto_manager: None,
        stream_id: None,
    };

    let mut rand = StdRng::seed_from_u64(1234);

    let mut sendr = Sender::new(s1, Handshake::Connector);
    let mut recvr = Receiver::new(s2, Handshake::Connector);

    let message = Bytes::from(vec![5; 1024]);
    let spacing = Duration::from_micros(10); // 100MB/s

    let mut next_send_time = start + spacing;
    let mut current_time = start;
    let mut last_delta = Duration::default();

    let mut window = VecDeque::new();
    let mut bytes_received = 0;
    let window_size = Duration::from_secs(1);

    loop {
        if next_send_time <= current_time {
            sendr.handle_data((current_time, message.clone()), current_time);
            next_send_time += spacing
        }

        let sender_next_time = match sendr.next_action(current_time) {
            SenderAlgorithmAction::WaitUntilAck | SenderAlgorithmAction::WaitForData => None,
            SenderAlgorithmAction::WaitUntil(time) => Some(time),
            SenderAlgorithmAction::Close => None, // xxx
        };

        while let Some((packet, _)) = sendr.pop_output() {
            // drop?
            if rand.gen::<f64>() > 0.01 {
                recvr.handle_packet(current_time, (packet, sender_addr));
            }
        }

        let receiver_next_time = loop {
            match recvr.next_algorithm_action(current_time) {
                ReceiverAlgorithmAction::TimeBoundedReceive(time) => break Some(time),
                ReceiverAlgorithmAction::SendControl(cp, _) => {
                    sendr.handle_packet((cp.into(), receiver_addr), current_time)
                }
                ReceiverAlgorithmAction::OutputData((_, payload)) => {
                    bytes_received += payload.len();
                    window.push_back((current_time, payload.len()));

                    while let Some((a, bytes)) = window.front() {
                        if current_time - *a > window_size {
                            bytes_received -= *bytes;
                            window.pop_front();
                        } else {
                            break;
                        }
                    }

                    // dbg!(window.len(), current_time - window.front().unwrap_or(&(current_time, 0)).0);

                    print!(
                        "Received {:20.3}MB, rate={:20.3}MB/s snd={:?} delta={:>10}\r",
                        bytes_received as f64 / 1024. / 1024.,
                        bytes_received as f64 / 1024. / 1024. / window_size.as_secs_f64(),
                        sendr.snd_timer.period(),
                        format!("{:?}", last_delta)
                    );
                } // xxx
                ReceiverAlgorithmAction::Close => break None,
            }
        };

        let new_current = [Some(next_send_time), sender_next_time, receiver_next_time]
            .iter()
            .copied()
            .filter_map(identity)
            .min()
            .unwrap();

        if next_send_time == new_current {
            trace!("Waking up to give data to sender");
        }
        if sender_next_time == Some(new_current) {
            trace!("Waking up from sender")
        }
        if receiver_next_time == Some(new_current) {
            trace!("Waking up from receiver")
        }

        last_delta = new_current - current_time;
        debug!("Delta = {:?}", last_delta);
        current_time = new_current;
    }
}
