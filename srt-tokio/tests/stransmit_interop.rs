#![recursion_limit = "256"]
use std::io::ErrorKind;
use std::net::{SocketAddr, SocketAddrV4};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Error;
use bytes::Bytes;
use futures::{future::try_join, join, stream, SinkExt, Stream, StreamExt};
use log::info;

use tokio::net::UdpSocket;
use tokio::time::interval;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use srt_tokio::{ConnInitMethod, SrtSocketBuilder};

macro_rules! allow_not_found {
    ($x:expr) => {
        match $x {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if std::env::var("SRT_ALLOW_NO_INTEROP_TESTS").is_ok() {
                    log::error!("could not find executable, skipping");
                    return Ok(());
                } else {
                    return Err(e.into());
                }
            }
            Err(e) => return Err(e.into()),
            Ok(s) => s,
        }
    };
}

fn counting_stream(packets: u32, delay: Duration) -> impl Stream<Item = Bytes> {
    stream::iter(0..packets)
        .map(|i| Bytes::from(i.to_string()))
        .zip(interval(delay))
        .map(|(b, _)| b)
}

async fn udp_recvr(packets: u32, port: u16) -> Result<(), Error> {
    // start udp listener
    let socket = UdpFramed::new(
        UdpSocket::bind(&SocketAddr::V4(SocketAddrV4::new(
            "127.0.0.1".parse().unwrap(),
            port,
        )))
        .await
        .unwrap(),
        BytesCodec::new(),
    );

    receiver(packets, socket.map(|i| i.unwrap().0.freeze())).await
}

async fn receiver(
    packets: u32,
    mut stream: impl Stream<Item = Bytes> + Unpin,
) -> Result<(), Error> {
    let mut i = 0;
    while let Some(a) = stream.next().await {
        assert_eq!(&a, &i.to_string());

        i += 1;

        info!("Got pack!");

        // stransmit does not totally care if it sends 100% of it's packets
        // (which is prob fair), just make sure that we got at least 2/3s of it
        if i >= packets * 2 / 3 {
            info!("Got enough packs! Exiting!");
            break;
        }
    }
    assert!(i >= packets * 2 / 3);

    Ok(())
}

async fn udp_sender(packets: u32, port: u16) -> Result<(), Error> {
    let mut sock = UdpFramed::new(UdpSocket::bind("127.0.0.1:0").await?, BytesCodec::new());

    let mut stream = counting_stream(packets, Duration::from_millis(1))
        .map(|b| Ok((b, ([127, 0, 0, 1], port).into())));

    sock.send_all(&mut stream).await?;
    sock.close().await?;

    Ok(())
}

#[tokio::test]
async fn stransmit_client() -> Result<(), Error> {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // stranmsit process
    let mut stransmit = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2002")
        .arg("srt://127.0.0.1:2003?latency=182")
        .arg("-a:no") // don't reconnect
        .spawn());

    let listener = async {
        // connect to process
        let mut conn = SrtSocketBuilder::new(ConnInitMethod::Listen)
            .local_port(2003)
            .latency(Duration::from_millis(827))
            .connect()
            .await
            .unwrap();
        assert_eq!(
            conn.settings().send_tsbpd_latency,
            Duration::from_millis(827)
        );
        assert_eq!(
            conn.settings().recv_tsbpd_latency,
            Duration::from_millis(827)
        );

        let mut i = 0;

        // start the data generation process
        join!(async { udp_sender(PACKETS, 2002).await.unwrap() }, async {
            // receive
            while let Some(p) = conn.next().await {
                let (_, b) = p.unwrap();

                assert_eq!(&i.to_string(), &b);

                i += 1;

                if i > PACKETS * 2 / 3 {
                    break;
                }
            }
            assert!(i > PACKETS * 2 / 3);
        });
    };

    listener.await;
    stransmit.wait()?;

    Ok(())
}

// srt-rs connects to stransmit and sends to stransmit
#[tokio::test]
async fn stransmit_server() -> Result<(), Error> {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // start SRT connector
    let serv = async {
        let mut sender = SrtSocketBuilder::new_connect("127.0.0.1:2000")
            .latency(Duration::from_millis(99))
            .connect()
            .await
            .unwrap();

        assert_eq!(
            sender.settings().send_tsbpd_latency,
            Duration::from_millis(123)
        );
        assert_eq!(
            sender.settings().recv_tsbpd_latency,
            Duration::from_millis(123)
        );

        let mut stream =
            counting_stream(PACKETS, Duration::from_millis(1)).map(|b| Ok((Instant::now(), b)));
        sender.send_all(&mut stream).await.unwrap();
        sender.close().await.unwrap();
    };

    let udp_recv = async { udp_recvr(PACKETS, 2001).await.unwrap() };

    // start stransmit process
    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://:2000?latency=123?blocking=true")
        .arg("udp://127.0.0.1:2001")
        .arg("-a:no") // don't auto-reconnect
        .spawn());

    join!(serv, udp_recv);

    child.wait()?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn stransmit_rendezvous() -> Result<(), Error> {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let sender_fut = async move {
        let mut sender = SrtSocketBuilder::new_rendezvous("127.0.0.1:2004")
            .local_port(2005)
            .connect()
            .await
            .unwrap();

        sender
            .send_all(
                &mut counting_stream(PACKETS, Duration::from_millis(1))
                    .map(|b| Ok((Instant::now(), b))),
            )
            .await
            .unwrap();

        sender.close().await.unwrap();
    };

    let udp_recvr = async { udp_recvr(PACKETS, 2006).await.unwrap() };

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://127.0.0.1:2005?adapter=127.0.0.1&port=2004&mode=rendezvous")
        .arg("udp://127.0.0.1:2006")
        .arg("-a:no") // don't auto-reconnect
        .spawn());

    join!(sender_fut, udp_recvr);

    child.wait()?;

    Ok(())
}

#[tokio::test]
async fn stransmit_encrypt() -> Result<(), Error> {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("udp://:2007")
        .arg("srt://:2008?passphrase=password123&pbkeylen=16")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    let recvr_fut = async move {
        let recv = SrtSocketBuilder::new_connect("127.0.0.1:2008")
            .crypto(16, "password123")
            .connect()
            .await
            .unwrap();

        try_join(
            receiver(PACKETS, recv.map(|f| f.unwrap().1)),
            udp_sender(PACKETS, 2007),
        )
        .await
        .unwrap();
    };

    recvr_fut.await;
    child.wait().unwrap();

    Ok(())
}

#[tokio::test]
async fn stransmit_decrypt() -> Result<(), Error> {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    let sender_fut = async move {
        let mut snd = SrtSocketBuilder::new_listen()
            .crypto(16, "password123")
            .local_port(2009)
            .connect()
            .await
            .unwrap();

        snd.send_all(
            &mut counting_stream(PACKETS, Duration::from_millis(1))
                .map(|b| Ok((Instant::now(), b))),
        )
        .await
        .unwrap();
        info!("Send finished!");
        snd.close().await.unwrap();
        info!("Closed!");
    };

    let mut child = allow_not_found!(Command::new("srt-live-transmit")
        .arg("srt://127.0.0.1:2009?passphrase=password123&pbkeylen=16")
        .arg("udp://127.0.0.1:2010")
        .arg("-a:no")
        .arg("-loglevel:debug")
        .spawn());

    join!(sender_fut, async {
        udp_recvr(PACKETS, 2010).await.unwrap()
    });
    info!("Futures finished!");
    child.wait().unwrap();

    Ok(())
}
