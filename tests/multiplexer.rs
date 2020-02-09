use std::time::Instant;

use srt::{SenderStream, SrtCongestCtrl, SrtSocketBuilder};

use bytes::Bytes;
use failure::Error;
use futures::channel::oneshot;
use futures::future::join_all;
use futures::stream;
use futures::{FutureExt, SinkExt, StreamExt};
use log::info;

#[tokio::test]
async fn multiplexer() -> Result<(), Error> {
    let _ = env_logger::try_init();

    let (finished_send, finished_recv) = oneshot::channel();

    tokio::spawn(async {
        let mut server = SrtSocketBuilder::new_listen()
            .local_port(2000)
            .build_multiplexed()
            .await
            .unwrap()
            .boxed();

        let mut fused_finish = finished_recv.fuse();
        while let Some(Ok((settings, channel))) =
            futures::select!(res = server.next().fuse() => res, _ = fused_finish => None)
        {
            let mut sender = SenderStream::new(
                channel,
                SrtCongestCtrl,
                settings.settings,
                settings.handshake,
            );

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
            let mut recvr = SrtSocketBuilder::new_connect("127.0.0.1:2000")
                .connect()
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
    Ok(())
}
