use bytes::Bytes;
use futures::{channel::oneshot, future::join_all, stream, FutureExt, SinkExt, StreamExt};
use log::info;
use srt_protocol::accesscontrol::{AcceptParameters, RejectReason, StreamAcceptor};
use srt_tokio::{SrtSocket, SrtSocketBuilder};
use std::{io, net::SocketAddr, time::Instant};

struct AccessController;

impl StreamAcceptor for AccessController {
    fn accept(
        &mut self,
        streamid: Option<&str>,
        _ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason> {
        streamid.
    }
}

#[tokio::test]
async fn streamid() -> io::Result<()> {
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
        while let Some(Ok(result)) =
            futures::select!(res = server.next().fuse() => res, _ = fused_finish => None)
        {
            let mut sender: SrtSocket = result.into();

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
