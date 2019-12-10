use std::time::Instant;

use srt::{ConnInitMethod, SrtSocketBuilder};

use futures::{join, try_join, SinkExt, TryStreamExt};

use bytes::Bytes;

#[tokio::test]
#[ignore]
async fn crypto_exchange() {
    let sender = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .crypto(24, "password123".into())
        .local_port(2000)
        .connect();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:2000".parse().unwrap()))
        .crypto(24, "password123".into())
        .connect();

    let (mut sender, mut recvr) = try_join!(sender, recvr).unwrap();

    let s_fut = async {
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
    };

    let r_fut = async {
        let (_, by) = recvr.try_next().await.unwrap().unwrap();
        assert_eq!(&by[..], b"Hello");
    };

    join!(s_fut, r_fut);
}
