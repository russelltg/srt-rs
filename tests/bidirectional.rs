use srt::{ConnInitMethod, SrtSocket, SrtSocketBuilder};

use bytes::Bytes;
use futures::{join, stream, try_join, SinkExt, StreamExt, TryStreamExt};
use std::time::{Duration, Instant};
use tokio::spawn;
use tokio::time::interval;

#[tokio::test]
async fn bidirectional() {
    let _ = env_logger::try_init();

    const ITERS: u32 = 1_000;

    let a =
        SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:5000".parse().unwrap())).connect();
    let b = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(5000)
        .connect();

    let (a, b) = try_join!(a, b).unwrap();

    // have each send a bunch of stuff to each other
    let process = |side: SrtSocket| {
        async {
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
            s
        }
    };

    // wait until the end to close, so that we don't close the bidirectional socket
    let (mut a, mut b) = join!(process(a), process(b));
    try_join!(a.close(), b.close()).unwrap();
}
