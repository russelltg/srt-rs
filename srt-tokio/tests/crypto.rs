use std::{
    io,
    time::{Duration, Instant},
};

use srt_tokio::SrtSocket;

use assert_matches::assert_matches;
use bytes::Bytes;
use futures::{SinkExt, TryStreamExt};
use log::info;

use tokio::{spawn, time::sleep};

async fn test_crypto(size: u16) {
    let sender = SrtSocket::builder()
        .encryption(size, "password123")
        .listen_on(":2000");

    let recvr = SrtSocket::builder()
        .encryption(size, "password123")
        .call("127.0.0.1:2000", None);

    let t = spawn(async move {
        let mut sender = sender.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        info!("Sent!");
        sleep(Duration::from_secs(1)).await;
        sender.close().await.unwrap();
        info!("Sender closed");
    });

    let mut recvr = recvr.await.unwrap();
    let (_, by) = recvr.try_next().await.unwrap().unwrap();
    info!("Got data");
    assert_eq!(&by[..], b"Hello");
    recvr.close().await.unwrap();
    info!("Receiver closed");
    t.await.unwrap();
}

#[tokio::test]
async fn crypto_exchange() {
    let _ = pretty_env_logger::try_init();

    test_crypto(16).await;
    sleep(Duration::from_millis(100)).await;
    test_crypto(24).await;
    sleep(Duration::from_millis(100)).await;
    test_crypto(32).await;
}

#[tokio::test]
async fn bad_password() {
    let listener = SrtSocket::builder()
        .encryption(16, "password1234")
        .listen_on(":2000");

    let caller = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:2000", None);

    let listener_fut = spawn(async move {
        listener.await.unwrap();
    });

    let res = caller.await;
    assert_matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);

    assert_matches!(
        tokio::time::timeout(Duration::from_millis(100), listener_fut).await,
        Err(_)
    );
}

// TODO: mismatch
