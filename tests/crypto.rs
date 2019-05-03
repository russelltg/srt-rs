use std::time::Instant;

use srt::{ConnInitMethod, SrtSocketBuilder};

use futures::future::Future;
use futures::stream::{iter_ok, Stream};

use bytes::Bytes;

#[test]
fn crypto_exchange() {
    let sender = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .crypto(24, "password123".into())
        .local_port(2000)
        .build()
        .unwrap();

    let recvr = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:2000".parse().unwrap()))
        .crypto(24, "password123".into())
        .build()
        .unwrap();

    sender
        .join(recvr)
        .and_then(|(conna, connb)| {
            let sendr = conna.sender();
            let recvr = connb.receiver();

            let sender_future =
                iter_ok(Some((Instant::now(), Bytes::from("Hello")))).forward(sendr);

            let recvr_future = recvr
                .into_future()
                .map(|(object, _)| {
                    let (_, b) = object.unwrap();

                    assert_eq!(&b[..], b"Hello");
                })
                .map_err(|(e, _)| e);

            sender_future.join(recvr_future)
        })
        .wait()
        .unwrap();
}
