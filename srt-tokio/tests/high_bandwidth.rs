use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::Error;
use bytes::Bytes;
use futures::{stream, FutureExt, SinkExt, Stream, StreamExt};
use log::{error, info};
use tokio::select;

use srt_tokio::{options::*, SocketStatistics, SrtSocket};

fn stream_exact(duration: Duration) -> impl Stream<Item = Bytes> {
    let message = Bytes::from(vec![5; 1024]);
    let first = tokio::time::Instant::now();
    // This will momentarily double the data rate for the first few seconds, pushing the flow
    // window, send and receive buffers past their limits. The connection should recover once the
    // input data rate is stabilized.
    stream::unfold(
        (message, first, duration / 2),
        move |(message, last, d)| async move {
            tokio::time::sleep_until(last + d).await;
            if first.elapsed() < Duration::from_secs(3) {
                Some((message.clone(), (message, last + d, d)))
            } else {
                Some((message.clone(), (message, last + d, duration)))
            }
        },
    )
}

#[allow(clippy::large_enum_variant)]
enum Select {
    Message((Instant, Bytes)),
    Statistics(SocketStatistics),
}

#[tokio::test]
async fn high_bandwidth() -> Result<(), Error> {
    use srt_protocol::options::LiveBandwidthMode::*;
    let _ = pretty_env_logger::try_init();

    const RATE_MBPS: u64 = 50;
    let latency = Duration::from_millis(150);
    let buffer_size = ByteCount((latency.as_secs_f64() * (RATE_MBPS as f64 * 1_000_000.)) as u64);
    let sender_fut = async move {
        let mut sock = SrtSocket::builder()
            .latency(Duration::from_millis(150))
            .bandwidth(Estimated {
                expected: DataRate(RATE_MBPS * 1_000_000),
                overhead: Percent(20),
            })
            .set(|options| {
                options.sender.buffer_size = buffer_size * 10;
                options.connect.udp_send_buffer_size = ByteCount(5_000_000);
            })
            .call("127.0.0.1:6654", None)
            .await?;

        let mut stream_gbps = stream_exact(Duration::from_micros(1_000_000 / 1024 / RATE_MBPS))
            .map(|bytes| Ok((Instant::now(), bytes)))
            .boxed();

        info!("Sender all connected");

        sock.send_all(&mut stream_gbps).await?;

        sock.close().await
    };

    let recv_fut = async move {
        let mut sock = SrtSocket::builder()
            .set(|options| {
                options.receiver.buffer_size = buffer_size * 2;
                options.connect.udp_recv_buffer_size = ByteCount(5_000_000);
                options.session.statistics_interval = Duration::from_secs(1);
            })
            .latency(latency)
            .listen_on(":6654")
            .await?
            .fuse();

        let mut statistics = sock.get_mut().statistics().clone().fuse();

        let mut window = VecDeque::new();
        let mut bytes_received = 0;
        let window_size = Duration::from_secs(1);

        loop {
            use Select::*;
            let next = futures::select!(
                message = sock.next() => Message(message.unwrap().unwrap()),
                statistics = statistics.next() => Statistics(statistics.unwrap()),
                complete => break,
            );

            match next {
                Message((_, bytes)) => {
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
                Statistics(statistics) => {
                    println!("rx_unique_bytes: {:<30}", statistics.rx_unique_bytes);
                }
            }
        }
        Ok::<_, Error>(())
    };

    let send = tokio::spawn(sender_fut).fuse();
    let recv = tokio::spawn(recv_fut).fuse();
    let timeout = tokio::time::sleep(Duration::from_secs(60)).fuse();

    select!(
        result = send => error!("send: {:?}", result),
        result = recv => error!("recv: {:?}", result),
        _ = timeout => { }
    );

    Ok(())
}
