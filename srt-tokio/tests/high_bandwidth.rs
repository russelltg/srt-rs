use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::Error;
use bytes::Bytes;
use futures::{stream, SinkExt, Stream, StreamExt, TryStreamExt};
use log::info;
use srt_tokio::SrtSocketBuilder;

fn stream_exact(duration: Duration) -> impl Stream<Item = Bytes> {
    let message = Bytes::from(vec![5; 1024]);
    let last = tokio::time::Instant::now();
    stream::unfold((message, last, duration), |(message, last, d)| async move {
        tokio::time::sleep_until(last + d).await;
        Some((message.clone(), (message, last + d, d)))
    })
}

#[tokio::test]
async fn high_bandwidth() -> Result<(), Error> {
    let _ = pretty_env_logger::try_init();

    let sender_fut = async {
        let mut sock = SrtSocketBuilder::new_connect("127.0.0.1:6654")
            .latency(Duration::from_millis(150))
            .connect()
            .await?;

        const RATE_MBPS: u64 = 20;
        let mut stream_gbps = stream_exact(Duration::from_micros(1_000_000 / 1024 / RATE_MBPS))
            .map(|bytes| Ok((Instant::now(), bytes)))
            .boxed();

        info!("Sender all connected");

        sock.send_all(&mut stream_gbps).await?;

        sock.close().await
    };

    let recv_fut = async {
        let mut sock = SrtSocketBuilder::new_listen()
            .local_port(6654)
            .latency(Duration::from_millis(150))
            .connect()
            .await?;

        let mut window = VecDeque::new();
        let mut bytes_received = 0;
        let window_size = Duration::from_secs(1);

        while let Some((_, bytes)) = sock.try_next().await? {
            bytes_received += bytes.len();
            window.push_back((Instant::now(), bytes.len()));

            while let Some((a, bytes)) = window.front() {
                if Instant::now() - *a > window_size {
                    bytes_received -= *bytes;
                    window.pop_front();
                } else {
                    break;
                }
            }

            print!(
                "Received {:10.3}MB, rate={:10.3}MB/s\r",
                bytes_received as f64 / 1024. / 1024.,
                bytes_received as f64 / 1024. / 1024. / window_size.as_secs_f64(),
            );
        }

        Ok::<_, Error>(())
    };

    tokio::spawn(sender_fut);
    tokio::spawn(recv_fut);

    tokio::time::sleep(Duration::from_secs(60)).await;

    Ok(())
}
