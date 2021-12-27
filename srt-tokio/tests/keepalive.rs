use srt_tokio::SrtSocket;

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
        let mut s = SrtSocket::builder()
            .call("127.0.0.1:4444", None)
            .await
            .unwrap();

        sleep(Duration::from_secs(10)).await;

        s.send((Instant::now(), b"1234"[..].into())).await.unwrap();

        sleep(Duration::from_secs(1)).await;

        s.close().await.unwrap();
    };
    let r = async {
        let mut r = SrtSocket::builder().listen_on(":4444").await.unwrap();
        let res = r.try_next().await.unwrap().unwrap();
        assert_eq!(res.1, Bytes::from(&b"1234"[..]));
        let res = r.try_next().await.unwrap();
        assert_eq!(res, None);
        r.close().await.unwrap();
    };
    futures::join!(s, r);
}
