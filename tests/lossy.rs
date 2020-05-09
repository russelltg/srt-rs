use std::str;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use tokio::time::interval;

use srt::{ConnInitMethod, SrtSocketBuilder};

mod lossy_conn;
use crate::lossy_conn::LossyConn;

#[tokio::test]
async fn lossy() {
    let _ = env_logger::try_init();

    const ITERS: i32 = 1_000;

    // a stream of ascending stringified integers
    let counting_stream = stream::iter(0..ITERS)
        .zip(interval(Duration::from_millis(1)))
        .map(|(i, _)| Bytes::from(i.to_string()));

    // 5% packet loss, 20ms delay
    let (send, recv) =
        LossyConn::channel(0.05, Duration::from_millis(20), Duration::from_millis(4));

    let sender = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(1111)
        .latency(Duration::from_secs(8))
        .connect_with_sock(send);
    let recvr = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:1111".parse().unwrap()))
        .connect_with_sock(recv);

    let sender = async move {
        let mut sender = sender.await.unwrap();
        let mut stream = counting_stream.map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();
    };

    let receiver = async move {
        let mut recvr = recvr.await.unwrap();
        let mut next_data = 0;
        let mut dropped = 0;

        while let Some(payload) = recvr.next().await {
            let (ts, payload) = payload.unwrap();

            let diff_ms = ts.elapsed().as_millis();

            assert!(
                7900 < diff_ms && diff_ms < 8700,
                "Latency not in tolerance zone: {}ms",
                diff_ms
            );

            let actual: i32 = str::from_utf8(&payload[..]).unwrap().parse().unwrap();
            dropped += actual - next_data;

            next_data = actual + 1;
        }

        assert!(dropped < 15, "Expected less than 15 drops, got {}", dropped);
    };

    futures::join!(sender, receiver);
}
