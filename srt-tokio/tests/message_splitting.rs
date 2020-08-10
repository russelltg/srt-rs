use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use futures::prelude::*;

use srt_tokio::{ConnInitMethod, SrtSocketBuilder};

const PACKET_SIZE: usize = 1 << 19;

#[tokio::test]
async fn message_splitting() -> Result<()> {
    env_logger::init();

    let sender = SrtSocketBuilder::new_connect("127.0.0.1:11124").connect();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(11124)
        .connect();

    // send a really really long packet
    let long_message = Bytes::from(&[b'8'; PACKET_SIZE][..]);

    tokio::spawn(async move {
        let mut sender = sender.await?;
        sender.send((Instant::now(), long_message)).await?;
        sender.close().await?;
        Ok(()) as Result<_>
    });

    tokio::spawn(async move {
        let data_vec = recvr.await.unwrap().collect::<Vec<_>>().await;
        assert_eq!(
            &data_vec
                .iter()
                .map(|r| r.as_ref().unwrap())
                .map(|(_, b)| b)
                .collect::<Vec<_>>(),
            &[&Bytes::from(&[b'8'; PACKET_SIZE][..])]
        );
    });

    Ok(())
}
