use srt_tokio::SrtSocketBuilder;
use std::time::{Duration, Instant};
use tokio::time::interval;

use bytes::Bytes;

use futures::prelude::*;

// Sending 1 every second for 30 seconds
#[tokio::test]
async fn receiver_timeout() {
    let _ = env_logger::try_init();

    let a = SrtSocketBuilder::new_listen().local_port(1872).connect();
    let b = SrtSocketBuilder::new_connect("127.0.0.1:1872").connect();

    const ITERS: usize = 30;

    let sender = async move {
        let mut counting_stream = stream::iter(0..ITERS)
            .zip(interval(Duration::from_secs(1)))
            .map(|(i, _)| Ok((Instant::now(), Bytes::from(i.to_string()))));

        let mut s = a.await.unwrap();
        s.send_all(&mut counting_stream).await.unwrap();
        s.close().await.unwrap();
    };

    let recvr = async move {
        let mut r = b.await.unwrap();
        for i in 0..ITERS {
            let (_, data) = r.try_next().await.unwrap().unwrap();
            assert_eq!(data, Bytes::from(i.to_string()));
        }
        assert_eq!(r.try_next().await.unwrap(), None);
    };
    futures::join!(sender, recvr);
}
