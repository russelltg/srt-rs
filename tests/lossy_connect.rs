mod lossy_conn;

use std::future::Future;
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::Error;
use futures::channel::oneshot;
use futures::{join, select, FutureExt, SinkExt};

use log::info;
use srt::{ConnInitMethod, SrtSocket, SrtSocketBuilder};

use lossy_conn::LossyConn;

#[tokio::test]
async fn connect() {
    let _ = env_logger::try_init();

    // super lossy channel, lots of reordering
    let (send, recv) =
        LossyConn::channel(0.70, Duration::from_millis(20), Duration::from_millis(20));

    let a = SrtSocketBuilder::new(ConnInitMethod::Listen)
        .local_port(1111)
        .connect_with_sock(send);
    let b = SrtSocketBuilder::new(ConnInitMethod::Connect("127.0.0.1:1111".parse().unwrap()))
        .connect_with_sock(recv);

    let (s1, r1) = oneshot::channel();
    let (s2, r2) = oneshot::channel();

    // This test is actually pretty involved
    // The futures don't resolve at the same times, and the senders need to be
    // polled after so they eventually resolve. But the receivers aren't being
    // polled, so just cancel after both are resolved, which is what the
    // oneshots are for.
    //
    // There's probably a better way to do it.
    async fn conn_close(
        sr: impl Future<Output = Result<SrtSocket, Error>>,
        s: oneshot::Sender<()>,
        r: oneshot::Receiver<()>,
    ) {
        let mut sock = sr.await.unwrap();
        s.send(()).unwrap();

        select! {
            _ = sock.send((Instant::now(), Bytes::new())).fuse() => {},
            _ = r.fuse() => {},
        };
    }
    join!(conn_close(a, s1, r2), conn_close(b, s2, r1));

    info!("All done");
}
