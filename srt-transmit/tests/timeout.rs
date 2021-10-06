use bytes::Bytes;
use srt_tokio::SrtSocketBuilder;
use std::{env, path::PathBuf, process::Stdio, time::Instant};

use futures::prelude::*;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::{sleep, Duration},
};

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

    let b = SrtSocketBuilder::new_connect("127.0.0.1:1878").connect();

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
#[ignore]
async fn sender_timeout() {
    let _ = pretty_env_logger::try_init();

    let b = SrtSocketBuilder::new_listen().local_port(1879).connect();

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
        // let mut b = b.await.unwrap();
        // assert_eq!(
        //     b.try_next().await.unwrap().as_ref().map(|t| &*t.1),
        //     Some(&b"asdf"[..])
        // );
        // assert_eq!(b.try_next().await.unwrap(), None);
    };
    futures::join!(sender, recvr);
}
