use std::time::{Duration, Instant};

use srt::SrtSocketBuilder;

use futures::{SinkExt, TryStreamExt};

use bytes::Bytes;

use tokio::{spawn, time::delay_for};

async fn test_crypto(size: u8) {
    let _ = env_logger::try_init();

    let sender = SrtSocketBuilder::new_listen()
        .crypto(size, "password123")
        .local_port(2000)
        .connect();

    let recvr = SrtSocketBuilder::new_connect("127.0.0.1:2000")
        .crypto(size, "password123")
        .connect();

    spawn(async move {
        let mut sender = sender.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    });

    let mut recvr = recvr.await.unwrap();
    let (_, by) = recvr.try_next().await.unwrap().unwrap();
    assert_eq!(&by[..], b"Hello");
    recvr.close().await.unwrap();
}

#[tokio::test]
async fn crypto_exchange() {
    test_crypto(16).await;
    delay_for(Duration::from_millis(100)).await;
    test_crypto(24).await;
    delay_for(Duration::from_millis(100)).await;
    test_crypto(32).await;
}

// TODO: bad password
// TODO: mismatch
