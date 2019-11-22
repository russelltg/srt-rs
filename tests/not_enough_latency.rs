/// A test testing if a connection is setup with not enough latency, ie rtt > 3ish*latency
use std::str;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{stream::iter, SinkExt, StreamExt};
use log::{debug, info};
use tokio::time::interval;

use srt::{ConnectionSettings, Receiver, Sender, SeqNumber, SocketID, SrtCongestCtrl};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[tokio::test]
async fn not_enough_latency() {
    env_logger::init();

    const INIT_SEQ_NUM: u32 = 12314;
    const PACKETS: u32 = 1_000;

    // a stream of ascending stringified integers
    // 1 ms between packets
    let counting_stream = iter(INIT_SEQ_NUM..INIT_SEQ_NUM + PACKETS)
        .map(|i| Bytes::from(i.to_string()))
        .zip(interval(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 4% packet loss, 4 sec latency with 0.2 s variance
    let (send, recv) = LossyConn::channel(0.04, Duration::from_secs(4), Duration::from_millis(200));

    let mut sender = Sender::new(
        send,
        SrtCongestCtrl,
        ConnectionSettings {
            init_seq_num: SeqNumber::new_truncate(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(81),
            local_sockid: SocketID(13),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
            tsbpd_latency: Duration::from_secs(5), // five seconds TSBPD, should be loss
            handshake_returner: Box::new(|_| None),
        },
    );

    let mut recvr = Receiver::new(
        recv,
        ConnectionSettings {
            init_seq_num: SeqNumber::new_truncate(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: Duration::from_secs(5),
            handshake_returner: Box::new(|_| None),
        },
    );

    tokio::spawn(async move {
        let mut stream = counting_stream.map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();

        info!("Sender exiting");
    });

    tokio::spawn(async move {
        let mut last_seq_num = INIT_SEQ_NUM - 1;

        let mut total = 0;

        while let Some(by) = recvr.next().await {
            let (ts, by) = by.unwrap();

            total += 1;

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
            let diff_ms = ts.elapsed().as_millis();
            assert!(
                diff_ms > 4900 && diff_ms < 6000,
                "Time difference {}ms not within 4.7 sec and 6 sec",
                diff_ms,
            );
        }

        // make sure we got 3/4 of the packets
        assert!(
            total > PACKETS * 3 / 4,
            "total={}, expected={}",
            total,
            PACKETS * 3 / 4
        );

        info!("Reciever exiting");
    });
}
