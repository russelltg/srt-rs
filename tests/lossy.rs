use std::str;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::{format_err, Error};
use futures::{stream::iter_ok, Future, Sink, Stream};
use futures_timer::Interval;
use srt::{
    ConnectionSettings, HandshakeResponsibility, Receiver, Sender, SeqNumber, SocketID,
    SrtCongestCtrl,
};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[test]
fn test_with_loss() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 812_731;
    const ITERS: u32 = 10_000;

    // a stream of ascending stringified integers
    let counting_stream = iter_ok(INIT_SEQ_NUM..(INIT_SEQ_NUM + ITERS))
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_micros(100)))
        .map(|(b, _)| b);

    let (send, recv) = LossyConn::channel(0.05, Duration::from_secs(0), Duration::from_secs(0));

    let sender = Sender::new(
        send.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        SrtCongestCtrl,
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(81),
            local_sockid: SocketID(13),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
            tsbpd_latency: Duration::from_millis(100000),
            responsibility: HandshakeResponsibility::Request,
        },
    );

    let recvr = Receiver::new(
        recv.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: Duration::from_millis(100000),
            responsibility: HandshakeResponsibility::Respond,
        },
    );

    let t1 = thread::spawn(|| {
        sender
            .send_all(counting_stream.map(|b| (Instant::now(), b)))
            .map_err(|e: Error| panic!("{:?}", e))
            .wait()
            .unwrap();
    });

    let t2 = thread::spawn(|| {
        let mut next_data = INIT_SEQ_NUM;

        for payload in recvr.wait() {
            let (_, payload) = payload.unwrap();

            assert_eq!(next_data.to_string(), str::from_utf8(&payload[..]).unwrap());

            next_data += 1;
        }

        assert_eq!(next_data, INIT_SEQ_NUM + ITERS);
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
