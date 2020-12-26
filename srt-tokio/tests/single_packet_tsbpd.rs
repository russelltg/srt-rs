use srt_tokio::SrtSocketBuilder;

use bytes::Bytes;
use futures::prelude::*;
use log::info;

use std::time::{Duration, Instant};

/// Send a single packet, with a large tsbpd, then close. Make sure it gets delviered with the delay.
#[tokio::test]
async fn single_packet_tsbpd() {
    let _ = pretty_env_logger::try_init();

    let sender = SrtSocketBuilder::new_connect("127.0.0.1:3000")
        .latency(Duration::from_secs(5))
        .connect();

    let recvr = SrtSocketBuilder::new_listen()
        .local_port(3000)
        .latency(Duration::from_secs(2))
        .connect();

    // init the connection
    let (mut recvr, mut sender) = futures::try_join!(sender, recvr).unwrap();

    let recvr_fut = async move {
        let start = Instant::now();
        let (time, packet) = recvr
            .try_next()
            .await
            .unwrap()
            .expect("The receiver should've yielded an object");

        info!("Pack recvd");

        // should be around 5s later
        let delay_ms = start.elapsed().as_millis();
        assert!(
            delay_ms < 5500 && delay_ms > 4900,
            "Was not around 5s later, was {}ms",
            delay_ms
        );

        assert_eq!(&packet, "Hello World!");

        let expected_displacement = Duration::from_millis(5);
        let displacement = if start > time {
            start - time
        } else {
            time - start
        };
        assert!(displacement < expected_displacement,
            "TsbPd time calculated for the packet should be close to `start` time\nExpected: < {:?}\nActual: {:?}\n",
            expected_displacement, displacement);

        // the recvr should return None now
        assert!(recvr.next().await.is_none());
    };

    let sendr_fut = async move {
        sender
            .send((Instant::now(), Bytes::from("Hello World!")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    };

    futures::join!(recvr_fut, sendr_fut);
}
