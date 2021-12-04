use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use futures::prelude::*;

use srt_tokio::SrtSocket;
use tokio::time::sleep;

const PACKET_SIZE: usize = 15 * 1500;

#[tokio::test]
async fn message_splitting() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    let sender = SrtSocket::new()
        .latency(Duration::from_secs(2))
        .call("127.0.0.1:11124", None);

    let recvr = SrtSocket::new()
        .latency(Duration::from_secs(2))
        .local_port(11124)
        .listen();

    // send a really really long packet
    let long_message = Bytes::from(&[b'8'; PACKET_SIZE][..]);

    let sender = tokio::spawn(async move {
        let mut sender = sender.await?;
        sender.send((Instant::now(), long_message)).await?;
        sleep(Duration::from_secs(5)).await;
        sender.close().await?;
        Ok(()) as Result<_>
    });

    let data_vec = recvr.await.unwrap().collect::<Vec<_>>().await;
    assert_eq!(
        &data_vec
            .iter()
            .map(|r| r.as_ref().unwrap())
            .map(|(_, b)| b)
            .collect::<Vec<_>>(),
        &[&Bytes::from(&[b'8'; PACKET_SIZE][..])]
    );

    sender.await.unwrap()?;

    Ok(())
}
