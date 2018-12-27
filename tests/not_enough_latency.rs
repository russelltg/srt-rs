/// A test testing if a connection is setup with not enough latency, ie rtt > 3ish*latency
use std::str;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::{format_err, Error};
use futures::{stream::iter_ok, Future, Sink, Stream};
use futures_timer::Interval;
use log::{debug, info};

use srt::{ConnectionSettings, Receiver, Sender, SeqNumber, SocketID, SrtCongestCtrl};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[test]
fn not_enough_latency() {
    env_logger::init();

    const INIT_SEQ_NUM: u32 = 12314;

    // a stream of ascending stringified integers
    // 1 ms between packets
    let counting_stream = iter_ok(INIT_SEQ_NUM..INIT_SEQ_NUM + 10000)
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 4% packet loss, 4 sec latency with 0.2 s variance
    let (send, recv) = LossyConn::channel(0.04, Duration::from_secs(4), Duration::from_millis(200));

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
            tsbpd_latency: Duration::from_secs(5), // five seconds TSBPD, should be loss
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
            tsbpd_latency: Duration::from_secs(5),
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

            // skip the first 100 packets, to allow for warmup
            if last_seq_num < INIT_SEQ_NUM + 100 {
                last_seq_num += 1;
                continue;
            }

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
            let diff_ms = (diff.as_secs() as f64 + f64::from(diff.subsec_nanos()) / 1e9) * 1e3;
            assert!(
                diff_ms > 4900. && diff_ms < 6000.,
                "Time difference {}ms not within 4.7 sec and 6 sec",
                diff_ms,
            );
        }

        info!("Reciever exiting");
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
