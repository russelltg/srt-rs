use std::time::Instant;

use bytes::Bytes;
use failure::Error;
use futures::prelude::*;
use log::info;

use srt::{ConnInitMethod, SrtSocketBuilder};

const PACKET_SIZE: usize = 1 << 19;

#[tokio::test]
async fn message_splitting() -> Result<(), Error> {
    env_logger::init();

    info!("Hi");

    let sender = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:11124".parse().unwrap()))
        .connect_sender();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(11124)
        .connect_receiver();

    let (sender, recvr) = futures::join!(sender, recvr);
    let (mut sender, recvr) = (sender?, recvr?);

    info!("Connected!");

    // send a really really long packet
    let long_message = Bytes::from(&[b'8'; PACKET_SIZE][..]);

    let (_, data_vec) = futures::join!(
        async {
            sender.send((Instant::now(), long_message)).await?;
            sender.close().await?;
            Ok(()) as Result<_, Error>
        },
        recvr.collect::<Vec<_>>()
    );

    assert_eq!(
        &data_vec
            .iter()
            .map(|r| r.as_ref().unwrap())
            .map(|(_, b)| b)
            .collect::<Vec<_>>(),
        &[&Bytes::from(&[b'8'; PACKET_SIZE][..])]
    );

    Ok(())
}
