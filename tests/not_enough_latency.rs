/// A test testing if a connection is setup with not enough latency, ie rtt > 3ish*latency
extern crate bytes;
extern crate futures;
extern crate futures_timer;
extern crate srt;
#[macro_use]
extern crate failure;
extern crate rand;
#[macro_use]
extern crate log;

use std::str;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::Error;
use futures::{stream::iter_ok, Future, Sink, Stream};
use futures_timer::Interval;
use srt::{
    ConnectionSettings, HandshakeResponsibility, Receiver, Sender, SeqNumber, SocketID,
    SrtCongestCtrl,
};

mod lossy_conn;
use lossy_conn::LossyConn;

#[test]
fn not_enough_latency() {
    const INIT_SEQ_NUM: u32 = 12314;

    // a stream of ascending stringified integers
    // 1 ms between packets
    let counting_stream = iter_ok(INIT_SEQ_NUM..INIT_SEQ_NUM + 10000)
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 4% packet loss, 4 sec latency with 0.2 s variance
    let (send, recv) = LossyConn::new(0.04, Duration::from_secs(4), Duration::from_millis(200));

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
            tsbpd_latency: Some(Duration::from_secs(5)), // five seconds TSBPD, should be loss
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
            tsbpd_latency: Some(Duration::from_secs(5)),
            responsibility: HandshakeResponsibility::Respond,
        },
    );

    let t1 = thread::spawn(move || {
        sender
            .send_all(counting_stream.map(|b| (Instant::now(), b)))
            .map_err(|e: Error| panic!(e))
            .wait()
            .unwrap();

        info!("Sender exiting");
    });

    let t2 = thread::spawn(move || {
        let mut last_seq_num = INIT_SEQ_NUM - 1;

        for by in recvr.wait() {
            let (ts, by) = by.unwrap();

            // they don't have to be sequential, but they should be increasing
            let this_seq_num = str::from_utf8(&by[..]).unwrap().parse().unwrap();
            assert!(
                this_seq_num > last_seq_num,
                "Sequence numbers aren't increasing"
            );
            if this_seq_num - last_seq_num > 1 {
                debug!("{} messages dropped", this_seq_num - last_seq_num - 1)
            }
            last_seq_num = this_seq_num;

            // make sure the timings are still decent
            let diff = Instant::now() - ts;
            let diff_ms = (diff.subsec_nanos() as f64 + diff.as_secs() as f64 * 1e9) * 1e-6;
            assert!(
                diff_ms > 4700. && diff_ms < 5300.,
                "Time difference {}ms not within 4.7 sec and 5.3 sec",
                diff_ms,
            );
        }

        info!("Reciever exiting");
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
