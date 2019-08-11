use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use futures::stream::iter_ok;
use futures::{Future, Sink, Stream};

use futures_timer::Interval;

use tokio_codec::BytesCodec;
use tokio_udp::UdpFramed;
use tokio_udp::UdpSocket;

use bytes::Bytes;

use srt::{ConnInitMethod, SrtSocketBuilder};

fn counting_stream(packets: u32, delay: Duration) -> impl Stream<Item = Bytes, Error = io::Error> {
    iter_ok(0..packets)
        .map(|i| From::from(i.to_string()))
        .zip(Interval::new(delay))
        .map(|(b, _)| b)
}

fn udp_recvr(packets: u32, port: u16) -> io::Result<thread::JoinHandle<()>> {
    // start udp listener
    thread::Builder::new()
        .name("udp recvr".to_string())
        .spawn(move || {
            let mut i = 0;
            for a in Stream::wait(UdpFramed::new(
                UdpSocket::bind(&SocketAddr::V4(SocketAddrV4::new(
                    "127.0.0.1".parse().unwrap(),
                    port,
                )))
                .unwrap(),
                BytesCodec::new(),
            )) {
                let (a, _) = a.unwrap();

                assert_eq!(&a, &i.to_string());

                i += 1;

                // stransmit does not totally care if it sends 100% of it's packets
                // (which is prob fair), just make sure that we got at least 2/3s of it
                if i >= packets * 2 / 3 {
                    break;
                }
            }
            assert!(i >= packets * 2 / 3);
        })
}

#[test]
fn stransmit_client() {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // stranmsit process
    let mut stransmit = Command::new("stransmit")
        .arg("udp://:2002")
        .arg("srt://127.0.0.1:2003?latency=182")
        .arg("-a:no") // don't reconnect
        .spawn()
        .unwrap();

    // SRT
    let srt = thread::Builder::new()
        .name("srt receiver".to_string())
        .spawn(|| {
            let srt = SrtSocketBuilder::new(ConnInitMethod::Listen)
                .local_port(2003)
                .latency(Duration::from_millis(827))
                .build()
                .unwrap();

            let conn = srt.wait().unwrap().receiver();

            assert_eq!(conn.settings().tsbpd_latency, Duration::from_millis(827));

            let mut i = 0;

            for p in conn.wait() {
                let (_, b) = p.unwrap();

                assert_eq!(&i.to_string(), &b);

                i += 1;

                if i > PACKETS * 2 / 3 {
                    break;
                }
            }

            assert!(i > PACKETS * 2 / 3);
        })
        .unwrap();

    // wait a minute for the connection to be established before sending data
    thread::sleep(Duration::from_millis(1000));

    // send on udp to SRT, on port 2002
    let udp_server = thread::Builder::new()
        .name("udp data generator".to_string())
        .spawn(|| {
            UdpFramed::new(
                UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap(),
                BytesCodec::new(),
            )
            .send_all(
                counting_stream(PACKETS, Duration::from_millis(1))
                    .map(|b| (b, "127.0.0.1:2002".parse().unwrap())),
            )
            .wait()
            .unwrap();
        })
        .unwrap();

    udp_server.join().unwrap();
    srt.join().unwrap();
    stransmit.wait().unwrap();
}

// srt-rs connects to stransmit and sends to stransmit
#[test]
fn stransmit_server() {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // start SRT connector
    let serv_thread = thread::Builder::new()
        .name("conenctor/sender".to_string())
        .spawn(|| {
            let sock =
                SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:2000".parse().unwrap()))
                    .latency(Duration::from_millis(99))
                    .build()
                    .unwrap();

            let conn = sock.wait().unwrap().sender();

            assert_eq!(conn.settings().tsbpd_latency, Duration::from_millis(123));

            conn.send_all(
                counting_stream(PACKETS, Duration::from_millis(1)).map(|b| (Instant::now(), b)),
            )
            .and_then(|(sink, _)| sink.flush())
            .wait()
            .unwrap();
        })
        .unwrap();

    let udp_thread = udp_recvr(PACKETS * 2 / 3, 2001).unwrap();

    // start stransmit process
    let mut child = Command::new("stransmit")
        .arg("srt://:2000?latency=123?blocking=true")
        .arg("udp://127.0.0.1:2001")
        .arg("-a:no") // don't auto-reconnect
        .spawn()
        .unwrap();

    serv_thread.join().unwrap();
    child.wait().unwrap();
    udp_thread.join().unwrap();
}

// #[test]
// fn stransmit_rendezvous() {
//     let _ = env_logger::try_init();

//     const PACKETS: u32 = 1_000;

//     let sender_thread = thread::spawn(move || {
//         let sock = SrtSocketBuilder::new(ConnInitMethod::Rendezvous(
//             "127.0.0.1:2004".parse().unwrap(),
//         ))
//         .local_port(2005)
//         .build()
//         .unwrap();

//         let conn = sock.wait().unwrap().sender();

//         conn.send_all(
//             counting_stream(PACKETS, Duration::from_millis(1)).map(|b| (Instant::now(), b)),
//         )
//         .wait()
//         .unwrap();
//     });

//     let udp_recvr = udp_recvr(PACKETS * 2 / 3, 2006).unwrap();

//     let stransmit = Command::new("stransmit")
//         .arg("srt://127.0.0.1:1234?mode=rendezvous")
//         .arg();
// }
