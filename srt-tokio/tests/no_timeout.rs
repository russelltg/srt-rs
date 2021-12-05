use srt_tokio::SrtSocket;
use std::time::{Duration, Instant};

use bytes::Bytes;

use futures::prelude::*;

// Sending 1 every second for 30 seconds
#[tokio::test]
async fn receiver_timeout() {
    let _ = pretty_env_logger::try_init();

    let a = SrtSocket::new().listen(":1876");
    let b = SrtSocket::new().call("127.0.0.1:1876", None);

    const ITERS: usize = 30;

    let sender = async move {
        let mut counting_stream =
            tokio_stream::StreamExt::throttle(stream::iter(0..ITERS), Duration::from_secs(1))
                .map(|i| Ok((Instant::now(), Bytes::from(i.to_string()))))
                .boxed();

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
