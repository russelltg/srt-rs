use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use tokio::time::interval;

use srt::{ConnectionSettings, Receiver, Sender, SeqNumber, SocketID, SrtCongestCtrl};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[tokio::test]
async fn lossy() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 0;
    const ITERS: u32 = 1_000;

    // a stream of ascending stringified integers
    let counting_stream = stream::iter(0..ITERS)
        .map(|i| Bytes::from(i.to_string()))
        .zip(interval(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 5% packet loss, 20ms delay
    let (send, recv) =
        LossyConn::channel(0.05, Duration::from_millis(20), Duration::from_millis(4));

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
            tsbpd_latency: Duration::from_secs(8),
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
            tsbpd_latency: Duration::from_secs(8),
            handshake_returner: Box::new(|_| None),
        },
    );

    let sender = async move {
        let mut stream = counting_stream.map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();
    };

    let receiver = async move {
        let mut next_data = 0;

        while let Some(payload) = recvr.next().await {
            let (ts, payload) = payload.unwrap();

            let diff_ms = ts.elapsed().as_millis();

            assert!(
                7900 < diff_ms && diff_ms < 8700,
                "Latency not in tolerance zone: {}ms",
                diff_ms
            );
            assert_eq!(&next_data.to_string(), &payload);

            next_data += 1;
        }

        assert_eq!(next_data, ITERS);
    };

    futures::join!(sender, receiver);
}
