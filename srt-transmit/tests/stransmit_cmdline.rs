use std::env;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use tokio_util::codec::{BytesCodec, Decoder};
use tokio_util::udp::UdpFramed;

use anyhow::Error;

use futures::{stream, FutureExt, SinkExt, StreamExt, TryStreamExt};

use bytes::{Bytes, BytesMut};

#[cfg(target_os = "windows")]
const STRANSMIT_NAME: &str = "srt-transmit.exe";
#[cfg(not(target_os = "windows"))]
const STRANSMIT_NAME: &str = "srt-transmit";

fn find_stransmit_rs() -> PathBuf {
    let mut stransmit_rs_path = env::current_exe().unwrap();
    stransmit_rs_path.pop();

    stransmit_rs_path.push(STRANSMIT_NAME);

    if !stransmit_rs_path.exists() {
        stransmit_rs_path.pop();
        stransmit_rs_path.pop();
        stransmit_rs_path.push(STRANSMIT_NAME);
    }

    assert!(
        stransmit_rs_path.exists(),
        "Could not find stransmit at {:?}",
        stransmit_rs_path
    );

    stransmit_rs_path
}

struct ChunkDecoder {
    size: usize,
}

impl ChunkDecoder {
    pub fn new(size: usize) -> Self {
        ChunkDecoder { size }
    }
}

impl Decoder for ChunkDecoder {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, std::io::Error> {
        if buf.len() >= self.size {
            let out = buf.split_to(self.size);
            buf.reserve(self.size);
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }
}

async fn build_receiver_socket(udp_out: u16, ident: i32) -> Result<UdpFramed<ChunkDecoder>, Error> {
    let len = format!("asdf{}", ident).len();
    Ok(UdpFramed::new(
        UdpSocket::bind(&SocketAddr::new("127.0.0.1".parse()?, udp_out)).await?,
        ChunkDecoder::new(len),
    ))
}

async fn udp_receiver(udp_out: u16, ident: i32) -> Result<(), Error> {
    let mut sock = build_receiver_socket(udp_out, ident).await?;
    udp_receiver_sock(&mut sock, ident).await
}

async fn udp_receiver_sock(sock: &mut UdpFramed<ChunkDecoder>, ident: i32) -> Result<(), Error> {
    let receive_data = async move {
        let mut i = 0;
        while let Some((pack, _)) = sock.try_next().await.unwrap() {
            assert_eq!(&pack, &format!("asdf{}", ident));

            // once we get 20, that's good enough for validity
            i += 1;
            if i > 20 {
                break;
            }
        }
    };
    // 10s timeout
    let succ = futures::select!(_ = receive_data.boxed().fuse() => true, _ = sleep(Duration::from_secs(10)).fuse() => false);
    assert!(succ, "Timeout with receiving");

    Ok::<_, Error>(())
}

async fn udp_sender(udp_in: u16, ident: i32) -> Result<(), Error> {
    let mut sock = UdpFramed::new(UdpSocket::bind("127.0.0.1:0").await?, BytesCodec::new());
    let mut stream =
        tokio_stream::StreamExt::throttle(stream::iter(0..100), Duration::from_millis(100))
            .map(|_| {
                Ok((
                    Bytes::from(format!("asdf{}", ident)),
                    SocketAddr::new("127.0.0.1".parse().unwrap(), udp_in),
                ))
            })
            .boxed();
    sock.send_all(&mut stream).await.unwrap();

    Ok::<_, Error>(())
}

async fn wait_for(mut a: Child, mut b: Child, failure_str: &str) -> Result<(), Error> {
    futures::select! {
        r_a = a.wait().fuse() => { r_a.expect(failure_str); },
        r_b = b.wait().fuse() => { r_b.expect(failure_str); },
        _ = sleep(Duration::from_secs(10)).fuse() => {
            a.kill().await.expect(failure_str);
            b.kill().await.expect(failure_str);
        }
    }

    Ok::<_, Error>(())
}

async fn test_send(
    udp_in: u16,
    args_a: &'static [&str],
    args_b: &'static [&str],
    udp_out: u16,
) -> Result<(), Error> {
    let srs_path = find_stransmit_rs();

    let a = Command::new(&srs_path).args(args_a).spawn()?;
    let b = Command::new(&srs_path).args(args_b).spawn()?;

    let ident: i32 = rand::random();

    let sender = udp_sender(udp_in, ident);
    let recvr = udp_receiver(udp_out, ident);

    futures::try_join!(recvr, sender)?;

    let failure_str = format!(
        "Failed send test. Args:\n\t{}\n\t{}\n",
        args_a.join(" "),
        args_b.join(" ")
    );

    wait_for(a, b, &failure_str).await
}

fn ui_test(flags: &[&str], stderr: &str) {
    let mut child = std::process::Command::new(find_stransmit_rs())
        .args(flags)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // wait for 10s for the process to exit
    for _ in 0..1000 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "failure test succeeded, it should fail");

            let mut string = String::new();
            child.stderr.unwrap().read_to_string(&mut string).unwrap();

            assert_eq!(
                string.lines().count(),
                stderr.lines().count(),
                "Line counnt differed. \nExpected: \n{}\nActual:\n{}",
                string,
                stderr
            );

            // windows puts stranmsit-rs.exe instead of stranmsit-rs, this isn't a real failure so just remove all .exe
            let string = string.replace(".exe", "");

            for (i, (a, b)) in string.lines().zip(stderr.lines()).enumerate() {
                let (a, b) = (a.trim(), b.trim());
                if a != b {
                    panic!(
                        "Line {} differed. Expected: {:?}\nActual:   {:?}\n",
                        i, a, b
                    );
                }
            }
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }

    panic!("Stransmit process that was supposed to fail with args\n\t{}\ndid not exit, it may have succeeded in setup.", flags.join(" "));
}

mod stransmit_rs_snd_rcv {
    use super::test_send;
    use crate::{build_receiver_socket, find_stransmit_rs, udp_receiver_sock, udp_sender};
    use anyhow::Error;
    use tokio::process::Command;

    #[tokio::test]
    async fn basic() -> Result<(), Error> {
        test_send(
            2900,
            &["udp://:2900", "srt://127.0.0.1:2901"],
            &["srt://:2901", "udp://127.0.0.1:2902"],
            2902,
        )
        .await
    }

    // Windows CI doesn't seem to like these tests, but it passes on non-ci machines.
    // The hope is if there's a regression, it'll show up in linux or macos.
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn basic_tcp() -> Result<(), Error> {
        test_send(
            3000,
            &["udp://:3000", "tcp://127.0.0.1:3001"],
            &["tcp://:3001", "udp://127.0.0.1:3002"],
            3002,
        )
        .await
    }

    #[tokio::test]
    async fn sender_as_listener() -> Result<(), Error> {
        test_send(
            2003,
            &["udp://:2003", "srt://:2004"],
            &["srt://127.0.0.1:2004", "udp://127.0.0.1:2005"],
            2005,
        )
        .await
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn sender_as_listener_tcp() -> Result<(), Error> {
        test_send(
            3003,
            &["udp://:3003", "tcp://:3004"],
            &["tcp://127.0.0.1:3004", "udp://127.0.0.1:3005"],
            3005,
        )
        .await
    }

    #[tokio::test]
    async fn sender_as_listener_srt_local_port() -> Result<(), Error> {
        test_send(
            2006,
            &["udp://:2006", "srt://:2007"],
            &[
                "srt://127.0.0.1:2007?local_port=2008",
                "udp://127.0.0.1:2009",
            ],
            2009,
        )
        .await
    }

    #[tokio::test]
    async fn rendezvous() -> Result<(), Error> {
        test_send(
            3010,
            &[
                "udp://:3010",
                "srt://127.0.0.1:3012?rendezvous&local_port=3011",
            ],
            &[
                "srt://127.0.0.1:3011?rendezvous&local_port=3012",
                "udp://127.0.0.1:3013",
            ],
            3013,
        )
        .await
    }

    #[tokio::test]
    async fn stransmit_rs_rendezvous_udp_local_port() -> Result<(), Error> {
        test_send(
            2014,
            &[
                "udp://:2014",
                "srt://127.0.0.1:2016?rendezvous&local_port=2015",
            ],
            &[
                "srt://127.0.0.1:2015?rendezvous&local_port=2016",
                "udp://127.0.0.1:2018?local_port=2017",
            ],
            2018,
        )
        .await
    }

    #[tokio::test]
    async fn latency() -> Result<(), Error> {
        test_send(
            2019,
            &["udp://:2019", "srt://:2020?latency_ms=500"],
            &[
                "srt://127.0.0.1:2020?latency_ms=300",
                "udp://127.0.0.1:2021",
            ],
            2021,
        )
        .await
    }

    #[tokio::test]
    async fn udp_to_udp() -> Result<(), Error> {
        test_send(
            2022,
            &["udp://:2022", "udp://127.0.0.1:2023"],
            &["udp://:2023", "udp://127.0.0.1:2024"],
            2024,
        )
        .await
    }

    #[tokio::test]
    async fn multiplex() -> Result<(), Error> {
        test_send(
            2025,
            &["udp://:2025", "srt://:2026?multiplex"],
            &["srt://127.0.0.1:2026", "udp://127.0.0.1:2027"],
            2027,
        )
        .await
    }

    #[tokio::test]
    async fn encryption() -> Result<(), Error> {
        test_send(
            2028,
            &["udp://:2028", "srt://:2029?passphrase=passwordhello"],
            &[
                "srt://127.0.0.1:2029?passphrase=passwordhello",
                "udp://127.0.0.1:2030",
            ],
            2030,
        )
        .await
    }

    #[tokio::test]
    async fn encryption_pbkeylen() -> Result<(), Error> {
        test_send(
            2031,
            &[
                "udp://:2031",
                "srt://:2032?passphrase=passwordhello&pbkeylen=32",
            ],
            &[
                "srt://127.0.0.1:2032?passphrase=passwordhello&pbkeylen=32",
                "udp://127.0.0.1:2033",
            ],
            2033,
        )
        .await
    }

    #[tokio::test]
    async fn parse_hostname() -> Result<(), Error> {
        test_send(
            2034,
            &["udp://:2034", "srt://:2035"],
            &["srt://localhost:2035", "udp://localhost:2036"],
            2036,
        )
        .await
    }

    #[tokio::test]
    async fn ipv6() -> Result<(), Error> {
        test_send(
            3034,
            &["udp://:3034", "srt://:3035?interface=::1"],
            &["srt://[::1]:3035", "udp://localhost:3036"],
            3036,
        )
        .await
    }

    #[tokio::test]
    async fn reconnect() -> Result<(), Error> {
        let srs_path = find_stransmit_rs();

        let mut a = Command::new(&srs_path)
            .args(&["udp://:2037", "srt://127.0.0.1:2038?autoreconnect"])
            .spawn()
            .unwrap();

        let b_args = &["srt://:2038", "udp://127.0.0.1:2039"];
        let mut b = Command::new(&srs_path).args(b_args).spawn()?;

        let ident: i32 = rand::random();

        let mut recv_sock = build_receiver_socket(2039, ident).await?;

        let sender = udp_sender(2037, ident);
        let recvr = udp_receiver_sock(&mut recv_sock, ident);

        futures::try_join!(recvr, sender).unwrap();

        let failure_str = "Failed reconnect test";

        // it worked, restart b, send again
        b.kill().await.expect(failure_str);
        b.wait().await.expect(failure_str);

        let mut b = Command::new(&srs_path).args(b_args).spawn().unwrap();

        let sender = udp_sender(2037, ident);
        let recvr = udp_receiver_sock(&mut recv_sock, ident);

        futures::try_join!(recvr, sender).unwrap();

        a.kill().await.expect(failure_str);
        b.kill().await.expect(failure_str);

        a.wait().await.expect(failure_str);
        b.wait().await.expect(failure_str);

        Ok(())
    }
}

macro_rules! ui_tests {
    ($($n:ident),+) => {
        $(
            #[test]
            fn $n() {
                super::ui_test(
                    &include!(concat!("ui/", stringify!($n), ".cmdline")),
                    include_str!(concat!("ui/", stringify!($n), ".stderr"))
                )
            }
        )+
    };
}

mod stransmit_rs_ui {
    ui_tests!(
        no_args,
        udp_send_as_first,
        udp_recv_as_second,
        rendezvous_no_host,
        local_port_udp_recv,
        local_port_srt_listen,
        multiplex_connect,
        multiplex_recv,
        multiplex_parameter,
        bad_pbkeylen,
        bad_pbkeylen_str,
        pbkeylen_no_pw
    );
}
