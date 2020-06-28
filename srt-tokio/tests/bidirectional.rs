use srt_tokio::SrtSocketBuilder;

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt, TryStreamExt};
use std::time::{Duration, Instant};
use tokio::spawn;
use tokio::time::interval;

#[tokio::test]
async fn bidirectional() {
    let _ = env_logger::try_init();

    const ITERS: u32 = 1_000;

    let a = SrtSocketBuilder::new_connect("127.0.0.1:5000").connect();
    let b = SrtSocketBuilder::new_listen().local_port(5000).connect();

    for fut in vec![a, b] {
        spawn(async move {
            let side = fut.await.unwrap();
            let (mut s, mut r) = side.split();

            spawn(async move {
                for i in 0..ITERS {
                    let (_, payload) = r.try_next().await.unwrap().unwrap();

                    assert_eq!(payload, Bytes::from(i.to_string()));
                }
                assert_eq!(r.try_next().await.unwrap(), None);
            });
            let mut counting_stream = stream::iter(0..ITERS)
                .zip(interval(Duration::from_millis(1)))
                .map(|(i, _)| Ok((Instant::now(), Bytes::from(i.to_string()))));

            s.send_all(&mut counting_stream).await.unwrap();
            s.close().await.unwrap();
        });
    }
}
