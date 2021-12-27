use std::time::Instant;

use srt_tokio::{SrtListener, SrtSocket};

use anyhow::Result;
use bytes::Bytes;
use futures::{channel::oneshot, future::join_all, stream, FutureExt, SinkExt, StreamExt};
use log::info;

#[tokio::test]
async fn multiplexer() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    let (finished_send, finished_recv) = oneshot::channel();

    let listener = tokio::spawn(async {
        let mut server = SrtListener::builder().bind(2000).await.unwrap();

        let mut incoming = server.incoming();
        let mut fused_finish = finished_recv.fuse();
        while let Some(request) =
            futures::select!(res = incoming.next().fuse() => res, _ = fused_finish => None)
        {
            let mut sender = request.accept(None).await.unwrap();
            let mut stream =
                stream::iter(Some(Ok((Instant::now(), Bytes::from("asdf")))).into_iter());

            tokio::spawn(async move {
                sender.send_all(&mut stream).await.unwrap();
                sender.close().await.unwrap();
                info!("Sender finished");
            });
        }
    });

    // connect 10 clients to it
    let mut join_handles = vec![];
    for _ in 0..3 {
        join_handles.push(tokio::spawn(async move {
            let mut recvr = SrtSocket::builder()
                .call("127.0.0.1:2000", None)
                .await
                .unwrap();
            info!("Created connection");

            let first = recvr.next().await;
            assert_eq!(first.unwrap().unwrap().1, "asdf");
            let second = recvr.next().await;
            assert!(second.is_none());

            info!("Connection done");
        }));
    }

    // close the multiplex server when all is done
    join_all(join_handles).await;
    info!("all finished");
    finished_send.send(()).unwrap();
    listener.await?;
    Ok(())
}

// crypto!!
