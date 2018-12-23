use std::str;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::{format_err, Error};
use futures::stream::{iter_ok, Stream};
use futures::{Future, Sink};
use futures_timer::Interval;

use srt::{
    ConnectionSettings, HandshakeResponsibility, Receiver, Sender, SeqNumber, SocketID,
    SrtCongestCtrl,
};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[test]
fn tsbpd() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 12314;
    const PACKET_COUNT: u32 = 1000;

    // a stream of ascending stringified integers
    // 1 ms between packets
    let counting_stream = iter_ok(INIT_SEQ_NUM..INIT_SEQ_NUM + PACKET_COUNT)
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 1% packet loss, 1 sec latency with 0.2 s variance
    let (send, recv) = LossyConn::channel(0.01, Duration::from_secs(1), Duration::from_millis(200));

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
            tsbpd_latency: Duration::from_secs(5), // five seconds TSBPD, should be plenty for no loss
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
            tsbpd_latency: Duration::from_secs(5),
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

    let t2 = thread::spawn(move || {
        let mut next_num = INIT_SEQ_NUM;

        let mut recvr = Some(recvr);

        while let Ok((by, recvr_new)) = recvr
            .take()
            .unwrap()
            .into_future()
            .map_err(|(e, _)| e)
            .wait()
        {
            // wait until the SRT handshake has been exchanged and TSBPD has started
            if recvr_new.tsbpd().is_none() {
                next_num += 1;
                continue;
            }

            let (ts, by) = by.unwrap();
            assert_eq!(
                str::from_utf8(&by[..]).unwrap(),
                next_num.to_string(),
                "Incorrect data, packets must be out of order"
            );

            // make sure the diff is ~5000ms
            let diff = Instant::now() - ts;
            let diff_ms = (diff.subsec_nanos() as f64 + diff.as_secs() as f64 * 1e9) * 1e-6;
            assert!(
                diff_ms > 4700. && diff_ms < 5300.,
                "Time difference {}ms not within 4.7 sec and 5.3 sec, packet #{}",
                diff_ms,
                next_num - INIT_SEQ_NUM
            );

            next_num += 1;

            recvr = Some(recvr_new);
        }

        assert_eq!(next_num, INIT_SEQ_NUM + PACKET_COUNT);
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
