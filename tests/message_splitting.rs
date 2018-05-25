extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate srt;
#[macro_use]
extern crate log;

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
        .map(|(sender, recvr)| (sender.sender(), recvr.receiver()))
        .and_then(|(mut sender, recvr)| {
            info!("Connected!");

            // send a really really long packet
            let long_message = bytes::BytesMut::from(&[b'8'; 16384][..]).freeze();

            sender
                .start_send(long_message)
                .expect("Failed to start send of long message");

            sender
                .flush()
                .map(|mut sender| {
                    info!("Sender flushed, closing");
                    sender.close()
                })
                .join(
                    recvr
                        .into_future()
                        .and_then(|(data, recvr)| {
                            info!("Got first data packet, waiting for closure");

                            // poll again, which should eventually return None
                            // this is necessary as the receiver needs to continue to get poll events to ACK.
                            recvr.into_future().map(|(empty_data, recvr)| {
                                assert_eq!(data.as_ref().unwrap().len(), 16384);
                                assert_eq!(&data.unwrap()[..], &[b'8'; 16384][..]);
                                assert!(empty_data.is_none());

                                info!("Got end of stream, good");

                                recvr
                            })
                        })
                        .map_err(|(err, _)| err),
                )
        })
        .wait()
        .unwrap();
}
