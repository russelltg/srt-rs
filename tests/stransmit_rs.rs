use std::env;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use tokio_codec::BytesCodec;
use tokio_udp::{UdpFramed, UdpSocket};

use futures_timer::{Delay, Interval};

use futures::future::{Either, Future};
use futures::stream::{iter_ok, Stream};

use bytes::Bytes;

fn find_stransmit_rs() -> PathBuf {
    let mut stransmit_rs_path = env::current_exe().unwrap();
    stransmit_rs_path.pop();
    stransmit_rs_path.pop();
    stransmit_rs_path.push("stransmit-rs");

    stransmit_rs_path
}

fn test_send(udp_in: u16, args_a: &'static [&str], args_b: &'static [&str], udp_out: u16) {
    let srs_path = find_stransmit_rs();

    let mut a = Command::new(&srs_path).args(args_a).spawn().unwrap();
    let mut b = Command::new(&srs_path).args(args_b).spawn().unwrap();

    let sender = thread::spawn(move || {
        use futures::sink::Sink;

        UdpFramed::new(
            UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap(),
            BytesCodec::new(),
        )
        .send_all(
            iter_ok(0..100)
                .zip(Interval::new(Duration::from_millis(100)))
                .map(|_| {
                    (
                        Bytes::from("asdf"),
                        SocketAddr::new("127.0.0.1".parse().unwrap(), udp_in),
                    )
                }),
        )
        .wait()
        .unwrap();
    });

    let recvr = thread::spawn(move || {
        let mut i = 0;

        let udp = UdpFramed::new(
            UdpSocket::bind(&SocketAddr::new("127.0.0.1".parse().unwrap(), udp_out)).unwrap(),
            BytesCodec::new(),
        )
        .into_future()
        .map_err(|(e, _)| e)
        .select2(Delay::new(Duration::from_secs(4)))
        .map_err(|e| match e {
            Either::A((e, _)) | Either::B((e, _)) => e,
        });

        let udp = match udp.wait().unwrap() {
            Either::A(((Some((_, _)), udp), _)) => udp,
            Either::A(_) => panic!("Stream ended unexpectedly"),
            Either::B(_) => panic!(
                "Timeout when waiting for data. Args:\n\t{}\n\t{}\n",
                args_a.join(" "),
                args_b.join(" ")
            ),
        };

        for a in udp.wait() {
            let (pack, _) = a.unwrap();

            assert_eq!(&pack, "asdf");

            // once we get 20, that's good enough for validity
            i += 1;
            if i > 20 {
                break;
            }
        }
        assert!(i > 20);
    });

    // don't unwrap here, to avoid not killing the processes
    let recvr_res = recvr.join();
    let sendr_res = sender.join();

    let failure_str = format!(
        "Failed send test. Args:\n\t{}\n\t{}\n",
        args_a.join(" "),
        args_b.join(" ")
    );

    // it worked, kill the processes
    a.kill().expect(&failure_str);
    b.kill().expect(&failure_str);

    a.wait().expect(&failure_str);
    b.wait().expect(&failure_str);

    recvr_res.expect(&failure_str);
    sendr_res.expect(&failure_str);

    thread::sleep(Duration::from_millis(100));
}

fn ui_test(flags: &[&str], stderr: &str) {
    let mut child = Command::new(find_stransmit_rs())
        .args(flags)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // wait for 1s for the process to exit
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "failure test succeeded, it should fail");

            let mut string = String::new();
            child.stderr.unwrap().read_to_string(&mut string).unwrap();
            if &string != stderr {
                panic!("Expected stderr did not match actual. Actual:\n{}\n\nExpected:\n{}\n", string, stderr);
            }

            return;
        }
        thread::sleep(Duration::from_millis(10));
    }

    panic!("Stransmit process that was supposed to fail with args\n\t{}\ndid not exit, it may have succeeded in setup.", flags.join(" "));
}

#[test]
fn stransmit_rs_basic() {
    test_send(
        2000,
        &["udp://:2000", "srt://127.0.0.1:2001"],
        &["srt://:2001", "udp://127.0.0.1:2002"],
        2002,
    );
}

#[test]
fn stransmit_rs_sender_as_listener() {
    test_send(
        2003,
        &["udp://:2003", "srt://:2004"],
        &["srt://127.0.0.1:2004", "udp://127.0.0.1:2005"],
        2005,
    );
}

#[test]
fn stransmit_rs_sender_as_listener_srt_local_port() {
    test_send(
        2006,
        &["udp://:2006", "srt://:2007"],
        &[
            "srt://127.0.0.1:2007?local_port=2008",
            "udp://127.0.0.1:2009",
        ],
        2009,
    );
}

#[test]
fn stransmit_rs_rendezvous() {
    test_send(
        2010,
        &[
            "udp://:2010",
            "srt://127.0.0.1:2012?rendezvous&local_port=2011",
        ],
        &[
            "srt://127.0.0.1:2011?rendezvous&local_port=2012",
            "udp://127.0.0.1:2013",
        ],
        2013,
    );
}

#[test]
fn stransmit_rs_rendezvous_udp_local_port() {
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
    );
}

#[test]
fn stransmit_rs_latency() {
    test_send(
        2019,
        &["udp://:2019", "srt://:2020?latency_ms=500"],
        &[
            "srt://127.0.0.1:2020?latency_ms=300",
            "udp://127.0.0.1:2021",
        ],
        2021,
    );
}

#[test]
fn stransmit_rs_udp_to_udp() {
    test_send(
        2022,
        &["udp://:2022", "udp://127.0.0.1:2023"],
        &["udp://:2023", "udp://127.0.0.1:2024"],
        2024,
    );
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
        local_port_srt_listen
    );
}
