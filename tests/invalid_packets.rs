use bytes::Bytes;
use futures::prelude::*;
use futures::stream;
use rand::Rng;
use srt::SrtSocketBuilder;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::interval;

// Send a bunch of invalid packets to the socket, making sure that it can handle it
#[tokio::test]
async fn invalid_packets() {
    let _ = env_logger::try_init();

    let sender = async {
        let mut sender = SrtSocketBuilder::new_connect("127.0.0.1:8876")
            .local_port(8877)
            .connect()
            .await
            .unwrap();

        let mut counting_stream = stream::iter(0..100)
            .zip(interval(Duration::from_millis(1)))
            .map(|(i, _)| Bytes::from(i.to_string()))
            .map(|b| Ok((Instant::now(), b)));

        sender.send_all(&mut counting_stream).await.unwrap();
        sender.close().await.unwrap();
    };
    let recvr = async {
        let mut recvr = SrtSocketBuilder::new_listen()
            .local_port(8876)
            .connect()
            .await
            .unwrap();

        for _ in 0..100 {
            recvr.try_next().await.unwrap().unwrap();
        }

        assert_eq!(recvr.try_next().await.unwrap(), None);
    };

    let garbage = async {
        let mut sock = UdpSocket::bind(&"127.0.0.1:0").await.unwrap();
        while let Some(_) = interval(Duration::from_millis(10)).next().await {
            let mut rng = rand::thread_rng();
            let mut to_send = vec![0; rng.gen_range(1, 1024)];
            for i in &mut to_send {
                *i = rng.gen();
            }

            sock.send_to(&to_send[..], "127.0.0.1:8876").await.unwrap();
            sock.send_to(&to_send[..], "127.0.0.1:8877").await.unwrap();
        }
    };

    futures::select! {
        _ = futures::future::join(sender, recvr).fuse() => {},
        _ = garbage.fuse() => {}
    }
}
