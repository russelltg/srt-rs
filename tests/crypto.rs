use std::time::Instant;

use srt::SrtSocketBuilder;

use futures::{SinkExt, TryStreamExt};

use bytes::Bytes;

use tokio::spawn;

#[tokio::test]
#[ignore]
async fn crypto_exchange() {
    let sender = SrtSocketBuilder::new_listen()
        .crypto(24, "password123".into())
        .local_port(2000)
        .connect();

    let recvr = SrtSocketBuilder::new_connect("127.0.0.1:2000")
        .crypto(24, "password123".into())
        .connect();

    spawn(async move {
        let mut sender = sender.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
    });

    spawn(async move {
        let mut recvr = recvr.await.unwrap();
        let (_, by) = recvr.try_next().await.unwrap().unwrap();
        assert_eq!(&by[..], b"Hello");
    });
}
