use std::{convert::TryFrom, io, net::SocketAddr, time::Instant};

use bytes::Bytes;
use futures::{stream, SinkExt, StreamExt};
use log::info;

use srt_protocol::{access::*, packet::*, settings::*};

use srt_tokio::SrtSocketBuilder;

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
                StandardAccessControlEntry::UserName(u) if u == "admin" => {
                    return Ok(AcceptParameters::new())
                }
                _ => continue,
            }
        }

        info!("rejecting, not admin");

        Err(RejectReason::Server(ServerRejectReason::Forbidden))
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let _ = pretty_env_logger::try_init();

    let mut server = SrtSocketBuilder::new_listen()
        .local_port(3333)
        .build_multiplexed_with_acceptor(AccessController)
        .await
        .unwrap()
        .boxed();

    while let Some(Ok(mut sender)) = server.next().await {
        let mut stream = stream::iter(
            Some(Ok((
                Instant::now(),
                Bytes::from(format!(
                    "Hello admin!! Your SID is {:?}",
                    sender.settings().stream_id
                )),
            )))
            .into_iter(),
        );

        tokio::spawn(async move {
            sender.send_all(&mut stream).await.unwrap();
            sender.close().await.unwrap();
            info!("Sender finished");
        });
    }
    Ok(())
}
