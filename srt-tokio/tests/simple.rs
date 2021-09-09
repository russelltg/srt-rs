use std::time::{Duration, Instant};

use anyhow::Error;
use bytes::Bytes;
use futures::prelude::*;
use srt_tokio::SrtSocketBuilder;
use tokio::time::sleep;

#[tokio::test]
async fn test() {
    let _ = pretty_env_logger::try_init();

    let sender_fut = async {
        let mut tx = SrtSocketBuilder::new_listen()
            .local_port(5223)
            .connect()
            .await?;

        let iter = ["1", "2", "3"];

        tx.send_all(&mut stream::iter(&iter).map(|b| Ok((Instant::now(), Bytes::from(*b)))))
            .await?;

        sleep(Duration::from_millis(10)).await;

        tx.close().await?;

        Ok::<_, Error>(())
    };

    let receiver_fut = async {
        let mut rx = SrtSocketBuilder::new_connect("127.0.0.1:5223")
            .connect()
            .await?;

        assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"1"[..].into()));
        assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"2"[..].into()));
        assert_eq!(rx.try_next().await?.map(|(_i, b)| b), Some(b"3"[..].into()));
        assert_eq!(rx.try_next().await?, None);

        Ok::<_, Error>(())
    };

    futures::try_join!(sender_fut, receiver_fut).unwrap();
}
