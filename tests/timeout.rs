use srt::SrtSocketBuilder;
use std::time::Instant;

use futures::prelude::*;

#[tokio::test]
async fn receiver_timeout() {
    let _ = env_logger::try_init();

    let a = SrtSocketBuilder::new_listen().local_port(1872).connect();
    let b = SrtSocketBuilder::new_connect("127.0.0.1:1872").connect();

    let (mut a, mut b) = futures::try_join!(a, b).unwrap();

    let sender = async move {
        a.send((Instant::now(), b"asdf"[..].into())).await.unwrap();
        // just drop sender, don't close!
    };

    let recvr = async move {
        assert_eq!(
            b.try_next().await.unwrap().as_ref().map(|t| &*t.1),
            Some(&b"asdf"[..])
        );
        assert_eq!(b.try_next().await.unwrap(), None);
    };
    futures::join!(sender, recvr);
}
