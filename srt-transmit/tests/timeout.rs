use std::{env, path::PathBuf, process::Stdio, time::Instant};

#[cfg(not(windows))]
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};

use bytes::Bytes;
use futures::prelude::*;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::{sleep, Duration},
};

use srt_tokio::SrtSocket;

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

#[tokio::test]
async fn receiver_timeout() {
    let _ = pretty_env_logger::try_init();

    let b = SrtSocket::builder().call("127.0.0.1:1878", None);

    let stranmsit_rs = find_stransmit_rs();
    let mut a = Command::new(&stranmsit_rs)
        .args(&["-", "srt://:1878"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    let sender = async move {
        a.stdin.as_mut().unwrap().write_all(b"asdf").await.unwrap();
        sleep(Duration::from_millis(2000)).await;

        a.kill().await.unwrap();
    };

    let recvr = async move {
        let mut b = b.await.unwrap();
        assert_eq!(
            b.try_next().await.unwrap().as_ref().map(|t| &*t.1),
            Some(&b"asdf"[..])
        );
        assert_eq!(b.try_next().await.unwrap(), None);
    };
    futures::join!(sender, recvr);
}

#[tokio::test]
async fn sender_timeout() {
    let _ = pretty_env_logger::try_init();

    let b = SrtSocket::builder().listen_on(1879);

    let stranmsit_rs = find_stransmit_rs();
    let mut a = Command::new(&stranmsit_rs)
        .args(&["srt://localhost:1879", "-"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let sender = async move {
        let mut b = b.await.unwrap();

        let mut got_done = false;
        for _ in 0..200 {
            if b.send((Instant::now(), Bytes::from_static(b"asdf\n")))
                .await
                .is_err()
            {
                got_done = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(got_done);
    };

    let recvr = async move {
        let mut out = BufReader::new(a.stdout.as_mut().unwrap());

        let mut line = String::new();
        for _ in 0..10 {
            out.read_line(&mut line).await.unwrap();
        }

        a.kill().await.unwrap();
    };
    futures::join!(sender, recvr);
}

// There doesn't seem to exist any crates for programmatically sending Ctrl+C events to a child process on Windows
// within Rust. One avenue to explore would be the raw winapi binding - GenerateConsoleCtrlEvent.

#[cfg(not(windows))]
#[tokio::test]
async fn sigint_termination_idle() {
    let _ = pretty_env_logger::try_init();
    
    let stranmsit_rs = find_stransmit_rs();
    let mut a = Command::new(&stranmsit_rs)
        .args(&["-", "-"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        
    sleep(Duration::from_millis(500)).await;
    let pid = Pid::from_raw(a.id().unwrap() as i32);
    kill(pid, Signal::SIGINT).unwrap();

    let out = a.wait().await.unwrap();
    assert_eq!(out.code().unwrap(), 130);
}

#[cfg(not(windows))]
#[tokio::test]
async fn sigint_termination_work() {
    let _ = pretty_env_logger::try_init();

    let b = SrtSocket::builder().listen_on(1880);

    let stranmsit_rs = find_stransmit_rs();
    let mut a = Command::new(&stranmsit_rs)
        .args(&["srt://localhost:1880", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let sender = async move {
        let mut b = b.await.unwrap();

        let mut got_done = false;
        for _ in 0..200 {
            if b.send((Instant::now(), Bytes::from_static(b"asdf\n")))
                .await
                .is_err()
            {
                got_done = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(got_done);
    };

    let recvr = async move {
        let mut out = BufReader::new(a.stdout.as_mut().unwrap());
        let mut line = String::new();

        for _ in 0..10 {
            out.read_line(&mut line).await.unwrap();
        }

        let pid = Pid::from_raw(a.id().unwrap() as i32);
        kill(pid, Signal::SIGINT).unwrap();

        let out = a.wait().await.unwrap();
        assert_eq!(out.code().unwrap(), 130);
    };

    futures::join!(sender, recvr);
}
