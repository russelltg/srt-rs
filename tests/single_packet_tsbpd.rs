use srt::{ConnInitMethod, SrtSocketBuilder};

use futures::prelude::{Future, Sink, Stream};
use futures::stream::iter_ok;

use failure::Error;

use bytes::Bytes;

use std::time::{Duration, Instant};

/// Send a single packet, with a large tsbpd, then close. Make sure it gets delviered with the delay.
#[test]
fn single_packet_tsbpd() {
    let _ = env_logger::try_init();

    let sender = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:3000".parse().unwrap()))
        .latency(Duration::from_secs(5))
        .build()
        .unwrap();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(3000)
        .latency(Duration::from_secs(2))
        .build()
        .unwrap();

    // init the connection
    let (sender, recvr) = sender.join(recvr).wait().unwrap();

    println!("Conn init");

    let (sender, recvr) = (sender.sender(), recvr.receiver());

    let start = Instant::now();

    let ((item, recvr), _) = recvr
        .into_future()
        .map_err(|(e, _)| e)
        .join(
            sender.send_all(iter_ok::<_, Error>(
                [(Instant::now(), Bytes::from("Hello World!"))]
                    .iter()
                    .cloned(),
            )),
        )
        .wait()
        .unwrap();

    println!("Pack recvd");

    let (time, packet) = item.unwrap();

    // should be around 5s later
    let delay = Instant::now() - start;
    let delay_ms = delay.as_secs() * 1_000 + u64::from(delay.subsec_nanos()) / 1_000_000;
    assert!(
        delay_ms < 5500 && delay_ms > 4900,
        "Was not around 5s later, was {}ms",
        delay_ms
    );

    assert_eq!(&packet, "Hello World!");

    // the time from the packet should be close to `start`, less than 5ms
    let diff = start - time;
    assert!(diff.as_secs() == 0 && diff.subsec_nanos() < 5_000_000);

    // the recvr should return None now
    let (item, _) = recvr.into_future().map_err(|(e, _)| e).wait().unwrap();

    assert_eq!(item, None);
}
