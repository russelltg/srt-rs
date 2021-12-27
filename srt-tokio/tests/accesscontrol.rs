use std::{convert::TryFrom, io, net::SocketAddr, time::Instant};

use bytes::Bytes;
use futures::{channel::oneshot, future::join_all, stream, FutureExt, SinkExt, StreamExt};
use log::info;

use srt_protocol::access::*;

use srt_tokio::{SrtListener, SrtSocket};

struct AccessController;

impl StreamAcceptor for AccessController {
    fn accept(
        &mut self,
        streamid: Option<&str>,
        ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason> {
        info!("Got request from {} for {:?}", ip, streamid);

        let mut acl = streamid
            .ok_or(RejectReason::Server(ServerRejectReason::HostNotFound))?
            .parse::<AccessControlList>()
            .map_err(|_| RejectReason::Server(ServerRejectReason::BadRequest))?;

        for entry in acl
            .0
            .drain(..)
            .filter_map(|a| StandardAccessControlEntry::try_from(a).ok())
        {
            match entry {
                StandardAccessControlEntry::UserName(_) => {}
                StandardAccessControlEntry::ResourceName(rn) => match rn.parse::<i32>() {
                    Ok(i) if i < 5 => return Ok(AcceptParameters::new()),
                    _ => return Err(ServerRejectReason::BadRequest.into()),
                },
                StandardAccessControlEntry::HostName(_) => {}
                StandardAccessControlEntry::SessionId(_) => {}
                StandardAccessControlEntry::Type(_) => {}
                StandardAccessControlEntry::Mode(_) => {}
            }
        }

        Err(RejectReason::Server(ServerRejectReason::Unimplemented))
    }
}

#[tokio::test]
async fn streamid() -> io::Result<()> {
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
    for i in 0..10 {
        join_handles.push(tokio::spawn(async move {
            let stream_id = format!(
                "{}",
                AccessControlList(vec![
                    StandardAccessControlEntry::UserName("russell".into()).into(),
                    StandardAccessControlEntry::ResourceName(format!("{}", i)).into()
                ])
            );

            let recvr = SrtSocket::builder()
                .call("127.0.0.1:2000", Some(stream_id.as_str()))
                .await;

            let mut recvr = recvr.unwrap();

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
    listener.await.unwrap();
    Ok(())
}
