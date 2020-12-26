use srt_tokio::SrtSocketBuilder;

use bytes::Bytes;
use futures::prelude::*;
use std::time::{Duration, Instant};
use tokio::time::sleep;

// Tests opening a connection, and waiting a while then sending stuff
// it should be able to keep the connection alive
// exp total time is 8 seconds, so this should timeout if KeepAlives's aren't properly implemented
#[tokio::test]
async fn keepalive() {
    let _ = pretty_env_logger::try_init();

    let s = async {
        let mut s = SrtSocketBuilder::new_connect("127.0.0.1:4444")
            .connect()
            .await
            .unwrap();

        sleep(Duration::from_secs(10)).await;

        s.send((Instant::now(), b"1234"[..].into())).await.unwrap();
        s.close().await.unwrap();
    };
    let r = async {
        let mut r = SrtSocketBuilder::new_listen()
            .local_port(4444)
            .connect()
            .await
            .unwrap();
        let res = r.try_next().await.unwrap().unwrap();
        assert_eq!(res.1, Bytes::from(&b"1234"[..]));
        let res = r.try_next().await.unwrap();
        assert_eq!(res, None);
        r.close().await.unwrap();
    };
    futures::join!(s, r);
}
