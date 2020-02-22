use srt::SrtSocketBuilder;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use log::info;

use std::time::{Duration, Instant};

/// Send a single packet, with a large tsbpd, then close. Make sure it gets delviered with the delay.
#[tokio::test]
async fn single_packet_tsbpd() {
    let _ = env_logger::try_init();

    let sender = SrtSocketBuilder::new_connect("127.0.0.1:3000")
        .latency(Duration::from_secs(5))
        .connect();

    let recvr = SrtSocketBuilder::new_listen()
        .local_port(3000)
        .latency(Duration::from_secs(2))
        .connect();

    // init the connection

    let recvr_fut = async move {
        let mut recvr = recvr.await.unwrap();
        let start = Instant::now();
        let (time, packet) = recvr
            .next()
            .await
            .expect("The receiver should've yielded an object")
            .unwrap();

        info!("Pack recvd");

        // should be around 5s later
        let delay_ms = start.elapsed().as_millis();
        assert!(
            delay_ms < 5500 && delay_ms > 4900,
            "Was not around 5s later, was {}ms",
            delay_ms
        );
        assert_eq!(&packet, "Hello World!");

        // the recvr should return None now
        assert!(recvr.next().await.is_none());

        // the time from the packet should be close to `start`, less than 5ms
        assert!(start - time < Duration::from_millis(5));
    };

    let sendr_fut = async move {
        let mut sender = sender.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello World!")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    };

    futures::join!(recvr_fut, sendr_fut);
}
