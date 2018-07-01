extern crate env_logger;
#[macro_use]
extern crate futures;
extern crate srt;
#[macro_use]
extern crate log;
extern crate bytes;
extern crate tokio_udp;

use bytes::Bytes;
use futures::prelude::*;
use srt::{ConnInitMethod, SrtSocketBuilder};
use std::time::Instant;

// Apparently this was an important omission from the futures crate. Unfortunate.
struct CloseFuture<T>(Option<T>);

impl<T: Sink> Future for CloseFuture<T> {
    type Item = T;
    type Error = T::SinkError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        try_ready!(
            self.0
                .as_mut()
                .expect("Polled CloseFuture after Async::Ready was returned")
                .close()
        );

        return Ok(Async::Ready(self.0.take().unwrap()));
    }
}

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
                .start_send((Instant::now(),long_message))
                .expect("Failed to start send of long message");

            sender
                .flush()
                .and_then(|sender| {
                    info!("Sender flushed, closing");

                    CloseFuture(Some(sender))
                })
                .join(recvr.collect())
        })
        // connection closed and data received
        .map(|(_, data_vec)| {
            assert_eq!(&data_vec.iter().map(|(_, b)| b).collect::<Vec<_>>(), &[&Bytes::from(&[b'8'; 16384][..])]);
        })
        .wait()
        .unwrap();
}
