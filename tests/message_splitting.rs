extern crate env_logger;
extern crate futures;
extern crate srt;
#[macro_use]
extern crate log;
extern crate bytes;
extern crate tokio_udp;

use bytes::Bytes;
use futures::prelude::*;
use srt::{ConnInitMethod, SrtSocketBuilder};

#[test]
fn message_splitting() {
    env_logger::init();

    let sender = SrtSocketBuilder::new(
        "127.0.0.1:0".parse().unwrap(),
        ConnInitMethod::Connect("127.0.0.1:11124".parse().unwrap()),
    ).build()
        .unwrap();

    let recvr = SrtSocketBuilder::new("127.0.0.1:11124".parse().unwrap(), ConnInitMethod::Listen)
        .build()
        .unwrap();

    sender
        .join(recvr)
        // conection resolved
        .and_then(|(sender, recvr)| {
            let (mut sender, recvr) = (sender.sender(), recvr.receiver());

            info!("Connected!");

            // send a really really long packet
            let long_message = Bytes::from(&[b'8'; 16384][..]);

            sender
                .start_send(long_message)
                .expect("Failed to start send of long message");

            sender
                .flush()
                .map(|mut sender| {
                    info!("Sender flushed, closing");
                    sender.close().expect("Failed to close sender");

                    sender
                })
                .join(recvr.collect())
        })
        // connection closed and data received
        .map(|(_, data_vec)| {
            assert_eq!(&data_vec, &[Bytes::from(&[b'8'; 16384][..])]);
        })
        .wait()
        .unwrap();
}
