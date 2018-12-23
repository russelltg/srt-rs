use std::process::Command;
use std::str;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use futures::{stream::iter_ok, Future, Sink, Stream};

use futures_timer::Interval;

use tokio_codec::BytesCodec;
use tokio_udp::UdpFramed;
use tokio_udp::UdpSocket;

use srt::{ConnInitMethod, SrtSocketBuilder};

#[test]
fn stransmit_client() {
    let _ = env_logger::try_init();

    const PACKETS: u32 = 1_000;

    // start SRT connector
    let serv_thread = thread::Builder::new()
        .name("conenctor/sender".to_string())
        .spawn(|| {
            let sock =
                SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:1234".parse().unwrap()))
                    .latency(Duration::from_millis(500))
                    .build()
                    .unwrap();

            let conn = sock.wait().unwrap().sender();

            let counting_stream = iter_ok(0..PACKETS)
                .map(|i| From::from(i.to_string()))
                .zip(Interval::new(Duration::from_micros(100)))
                .map(|(b, _)| b);

            conn.send_all(counting_stream.map(|b| (Instant::now(), b)))
                .and_then(|(sink, _)| sink.flush())
                .wait()
                .unwrap();

            println!("Done Sending");
        })
        .unwrap();

    // start udp listener
    let udp_thread = thread::Builder::new()
        .name("udp recvr".to_string())
        .spawn(|| {
            let mut i = 0;
            for a in Stream::wait(UdpFramed::new(
                UdpSocket::bind(&"127.0.0.1:2345".parse().unwrap()).unwrap(),
                BytesCodec::new(),
            )) {
                let (a, _) = a.unwrap();
                let a = u32::from_str(str::from_utf8(&a).unwrap()).unwrap();

                println!("Recv: {}", a);

                assert_eq!(a, i);

                i += 1;

                if i == PACKETS {
                    break;
                }
            }
            assert_eq!(i, PACKETS);
        })
        .unwrap();

    // start stransmit process
    let mut child = Command::new("stransmit")
        .arg("srt://:1234")
        .arg("udp://127.0.0.1:2345")
        // .arg("-a:no") // don't auto-reconnect
        .spawn()
        .unwrap();

    serv_thread.join().unwrap();
    child.wait().unwrap();
    udp_thread.join().unwrap();
}
