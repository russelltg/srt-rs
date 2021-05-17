use std::time::Instant;

use bytes::Bytes;
use srt_tokio::SrtSocketBuilder;

use futures::{join, prelude::*};

#[tokio::test]
async fn rendezvous() {
    let _ = pretty_env_logger::try_init();

    let a = SrtSocketBuilder::new_rendezvous("127.0.0.1:5000")
        .local_port(5001)
        .connect();

    let b = SrtSocketBuilder::new_rendezvous("127.0.0.1:5001")
        .local_port(5000)
        .connect();

    join!(
        async move {
            let mut a = a.await.unwrap();

            a.send((Instant::now(), Bytes::from_static(b"hi")))
                .await
                .unwrap();

            a.close().await.unwrap();
        },
        async move {
            let mut b = b.await.unwrap();

            assert_eq!(&*b.try_next().await.unwrap().unwrap().1, b"hi");
            assert_eq!(b.try_next().await.unwrap(), None);

            b.close().await.unwrap();
        }
    );
}
