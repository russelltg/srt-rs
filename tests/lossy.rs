use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::Error;
use futures::{stream::iter_ok, Future, Sink, Stream};
use futures_timer::Interval;
use srt::{ConnectionSettings, Receiver, Sender, SeqNumber, SocketID, SrtCongestCtrl};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[test]
fn lossy() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 0;
    const ITERS: u32 = 10_000;

    // a stream of ascending stringified integers
    let counting_stream = iter_ok(0..ITERS)
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 5% packet loss, 20ms delay
    let (send, recv) =
        LossyConn::channel(0.05, Duration::from_millis(20), Duration::from_millis(4));

    let sender = Sender::new(
        send,
        SrtCongestCtrl,
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(81),
            local_sockid: SocketID(13),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
            tsbpd_latency: Duration::from_secs(8),
        },
    );

    let recvr = Receiver::new(
        recv,
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: Duration::from_secs(8),
        },
    );

    let sender = thread::spawn(|| {
        sender
            .send_all(counting_stream.map(|b| (Instant::now(), b)))
            .map_err(|e: Error| panic!("{:?}", e))
            .wait()
            .unwrap();
    });

    let receiver = thread::spawn(|| {
        let mut next_data = 0;

        for payload in recvr.wait() {
            let (ts, payload) = payload.unwrap();

            let diff = Instant::now() - ts;
            let diff_ms = diff.as_secs() * 1_000 + u64::from(diff.subsec_nanos() / 1_000_000);

            assert!(
                7900 < diff_ms && diff_ms < 8700,
                "Latency not in tolerance zone: {}ms",
                diff_ms
            );
            assert_eq!(&next_data.to_string(), &payload);

            next_data += 1;
        }

        assert_eq!(next_data, ITERS);
    });

    sender.join().unwrap();
    receiver.join().unwrap();
}
