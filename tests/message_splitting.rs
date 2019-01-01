use std::time::Instant;

use bytes::Bytes;

use futures::prelude::*;
use futures::stream::iter_ok;

use failure::Error;

use log::info;

use srt::{ConnInitMethod, SrtSocketBuilder};

#[test]
fn message_splitting() {
    env_logger::init();

    let sender = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:11124".parse().unwrap()))
        .build()
        .unwrap();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(11124)
        .build()
        .unwrap();

    sender
        .join(recvr)
        // conection resolved
        .and_then(|(sender, recvr)| {
            let (sender, recvr) = (sender.sender(), recvr.receiver());

            info!("Connected!");

            // send a really really long packet
            let long_message = Bytes::from(&[b'8'; 16384][..]);

            sender
                .send_all(iter_ok::<_, Error>(Some((Instant::now(), long_message))))
                .join(recvr.collect())
        })
        // connection closed and data received
        .map(|(_, data_vec)| {
            assert_eq!(
                &data_vec.iter().map(|(_, b)| b).collect::<Vec<_>>(),
                &[&Bytes::from(&[b'8'; 16384][..])]
            );
        })
        .wait()
        .unwrap();
}
