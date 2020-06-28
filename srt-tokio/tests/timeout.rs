use srt_tokio::SrtSocketBuilder;
use std::{
    env,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use futures::prelude::*;
use tokio::time::{delay_for, Duration};

#[cfg(target_os = "windows")]
const STRANSMIT_NAME: &str = "srt-transmit.exe";
#[cfg(not(target_os = "windows"))]
const STRANSMIT_NAME: &str = "srt-transmit-rs";

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
    let _ = env_logger::try_init();

    let b = SrtSocketBuilder::new_connect("127.0.0.1:1872").connect();

    let stranmsit_rs = find_stransmit_rs();
    let mut a = Command::new(&stranmsit_rs)
        .args(&["-", "srt://:1872"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    let sender = async move {
        a.stdin.as_mut().unwrap().write_all(b"asdf").unwrap();
        delay_for(Duration::from_millis(2000)).await;

        a.kill().unwrap();
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
