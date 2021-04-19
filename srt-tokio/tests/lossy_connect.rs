mod lossy_conn;

use std::future::Future;
use std::{
    io,
    net::ToSocketAddrs,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::channel::oneshot;
use futures::{join, select, FutureExt, SinkExt};

use srt_protocol::Packet;
use srt_tokio::{SrtSocket, SrtSocketBuilder};

use lossy_conn::LossyConn;

async fn test<A, B>(a: A, b: B)
where
    A: Future<Output = io::Result<SrtSocket>>,
    B: Future<Output = io::Result<SrtSocket>>,
{
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
        sr: impl Future<Output = std::result::Result<SrtSocket, io::Error>>,
        s: oneshot::Sender<()>,
        r: oneshot::Receiver<()>,
    ) {
        let mut sock = sr.await.unwrap();
        sock.send((Instant::now(), Bytes::new())).await.unwrap();
        s.send(()).unwrap();

        select! {
            _ = sock.close().fuse() => {},
            _ = r.fuse() => {},
        };
    }
    join!(conn_close(a, s1, r2), conn_close(b, s2, r1));
}

// super lossy channel, lots of reordering
fn chan(a: impl ToSocketAddrs, b: impl ToSocketAddrs) -> (LossyConn<Packet>, LossyConn<Packet>) {
    LossyConn::channel(
        0.70,
        Duration::from_millis(20),
        Duration::from_millis(20),
        a,
        b,
    )
}

fn chan_seeded(
    a: impl ToSocketAddrs,
    b: impl ToSocketAddrs,
    seed: u64,
) -> (LossyConn<Packet>, LossyConn<Packet>) {
    LossyConn::with_seed(
        0.70,
        Duration::from_millis(20),
        Duration::from_micros(20),
        a,
        b,
        seed,
    )
}

// #[tokio::test]
// async fn connect() {
//     let _ = pretty_env_logger::try_init();

//     let (send, recv) = chan("127.0.0.1:1111", "127.0.0.1:0");

//     let a = SrtSocketBuilder::new_listen()
//         .local_port(1111)
//         .connect_with_sock(send);
//     let b = SrtSocketBuilder::new_connect("127.0.0.1:1111").connect_with_sock(recv);

//     test(a, b).await
// }

// #[tokio::test]
// async fn rendezvous() {
//     let _ = pretty_env_logger::try_init();

//     async fn test_rendezvous(send: LossyConn<Packet>, recv: LossyConn<Packet>) {
//         let a = SrtSocketBuilder::new_rendezvous("127.0.0.1:1511")
//             .local_port(1512)
//             .connect_with_sock(send);

//         let b = SrtSocketBuilder::new_rendezvous("127.0.0.1:1512")
//             .local_port(1511)
//             .connect_with_sock(recv);

//         test(a, b).await
//     }

//     // test previously failing seeds, plus a random one.
//     let once_failed_seeds = [6238456632165205646, 11248772458713142060];

//     for seed in &once_failed_seeds {
//         let (send, recv) = chan_seeded("127.0.0.1:1512", "127.0.0.1:1511", *seed);
//         test_rendezvous(send, recv).await;
//     }

//     let (send, recv) = chan("127.0.0.1:1512", "127.0.0.1:1511");
//     test_rendezvous(send, recv).await;
// }
