use srt::{ConnInitMethod, SrtSocketBuilder};

use bytes::Bytes;
use failure::Error;
use futures::{SinkExt, StreamExt};
use log::info;

use std::time::{Duration, Instant};

/// Send a single packet, with a large tsbpd, then close. Make sure it gets delviered with the delay.
#[tokio::test]
async fn single_packet_tsbpd() -> Result<(), Error> {
    let _ = env_logger::try_init();

    let sender = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:3000".parse().unwrap()))
        .latency(Duration::from_secs(5))
        .connect();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(3000)
        .latency(Duration::from_secs(2))
        .connect();

    // init the connection
    let (sender, recvr) = futures::join!(sender, recvr);
    let (mut sender, mut recvr) = (sender?, recvr?);

    info!("Conn init");

    let start = Instant::now();

    let recv_fut = recvr.next();

    let send_fut = async {
        sender
            .send((Instant::now(), Bytes::from("Hello World!")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    };

    let (item, _) = futures::join!(recv_fut, send_fut);

    info!("Pack recvd");

    let (time, packet) = item.expect("The receiver should've yielded an object")?;

    // should be around 5s later
    let delay_ms = start.elapsed().as_millis();
    assert!(
        delay_ms < 5500 && delay_ms > 4900,
        "Was not around 5s later, was {}ms",
        delay_ms
    );

    assert_eq!(&packet, "Hello World!");

    let expected_displacement = Duration::from_millis(1);
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

    Ok(())
}
