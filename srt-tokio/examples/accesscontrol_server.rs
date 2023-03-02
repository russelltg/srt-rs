use std::{convert::TryFrom, io, net::SocketAddr, time::Instant};

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use log::info;

use srt_tokio::{access::*, options::*, SrtListener};

fn access_control(stream_id: Option<&StreamId>, ip: SocketAddr) -> Result<(), RejectReason> {
    info!("Got request from {} for {:?}", ip, stream_id);

    let mut acl = stream_id
        .ok_or(RejectReason::Server(ServerRejectReason::HostNotFound))?
        .as_str()
        .parse::<AccessControlList>()
        .map_err(|_| RejectReason::Server(ServerRejectReason::BadRequest))?;

    for entry in acl
        .0
        .drain(..)
        .filter_map(|a| StandardAccessControlEntry::try_from(a).ok())
    {
        match entry {
            StandardAccessControlEntry::UserName(u) if u == "admin" => return Ok(()),
            _ => continue,
        }
    }

    info!("rejecting, not admin");

    Err(RejectReason::Server(ServerRejectReason::Forbidden))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let _ = pretty_env_logger::try_init();

    let (_server, mut incoming) = SrtListener::builder().bind(3333).await.unwrap();

    while let Some(request) = incoming.incoming().next().await {
        let stream_id = request.stream_id().cloned();
        match access_control(stream_id.as_ref(), request.remote()) {
            Ok(()) => {
                let mut sender = request.accept(None).await.unwrap();
                let mut stream = stream::iter(
                    Some(Ok((
                        Instant::now(),
                        Bytes::from(format!("Hello admin!! Your SID is {stream_id:?}")),
                    )))
                    .into_iter(),
                );

                tokio::spawn(async move {
                    sender.send_all(&mut stream).await.unwrap();
                    sender.close().await.unwrap();
                    info!("Sender finished");
                });
            }
            Err(reason) => {
                request.reject(reason).await.unwrap();
            }
        }
    }
    Ok(())
}
