use std::{
    io,
    time::{Duration, Instant},
};

use srt_tokio::SrtSocket;

use assert_matches::assert_matches;
use bytes::Bytes;
use futures::{SinkExt, TryStreamExt};
use log::info;
use tokio::{select, spawn, time::sleep};

async fn test_crypto(size_listen: u16, size_call: u16, port: u16) {
    let sender = SrtSocket::builder()
        .encryption(size_listen, "password123")
        .listen_on(port);

    let local_addr = format!("127.0.0.1:{port}");

    let recvr = SrtSocket::builder()
        .encryption(size_call, "password123")
        .call(local_addr.as_str(), None);

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

    test_crypto(16, 16, 2000).await;
    test_crypto(24, 24, 2001).await;
    test_crypto(32, 32, 2002).await;
}

#[tokio::test]
async fn key_size_mismatch() {
    test_crypto(32, 16, 2003).await;
    test_crypto(32, 0, 2004).await;
    test_crypto(0, 32, 2005).await;
}

#[tokio::test]
async fn bad_password_listen() {
    let listener = SrtSocket::builder()
        .encryption(16, "password1234")
        .listen_on(":3000");

    let caller = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3000", None);

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

#[tokio::test]
async fn bad_password_rendezvous() {
    let a = SrtSocket::builder()
        .local_port(5301)
        .encryption(16, "password1234")
        .rendezvous("127.0.0.1:5300");

    let b = SrtSocket::builder()
        .encryption(16, "password123")
        .local_port(5300)
        .rendezvous("127.0.0.1:5301");

    let result = select!(
        r = a => r,
        r = b => r
    );

    assert_matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);
}
