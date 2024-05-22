use std::{io, time::Instant};

use assert_matches::assert_matches;
use bytes::Bytes;
use futures::{future::try_join_all, stream, SinkExt, StreamExt};
use log::info;

use srt_protocol::{
    access::*, packet::CoreRejectReason, protocol::pending_connection::ConnectionReject,
    settings::KeySettings,
};

use srt_tokio::{
    options::{KeySize, StreamId},
    SrtListener, SrtSocket,
};

fn accept(streamid: Option<&StreamId>) -> Result<AcceptParameters, RejectReason> {
    info!("Got request for {:?}", streamid);

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
                _ => {
                    return Err(ServerRejectReason::BadRequest.into());
                }
            },
            StandardAccessControlEntry::HostName(_) => {}
            StandardAccessControlEntry::SessionId(_) => {}
            StandardAccessControlEntry::Type(_) => {}
            StandardAccessControlEntry::Mode(_) => {}
        }
    }

    Err(RejectReason::Server(ServerRejectReason::Unimplemented))
}

#[tokio::test]
async fn streamid() -> io::Result<()> {
    let _ = pretty_env_logger::try_init();

    let (mut server, mut incoming) = SrtListener::builder().bind(2000).await.unwrap();
    let listener = tokio::spawn(async move {
        while let Some(request) = incoming.incoming().next().await {
            tokio::spawn(async move {
                let mut sender = match accept(request.stream_id()) {
                    Ok(mut ap) => request.accept(ap.take_key_settings()).await.unwrap(),
                    Err(rr) => {
                        request.reject(rr).await.unwrap();
                        return;
                    }
                };

                let mut stream =
                    stream::iter(Some(Ok((Instant::now(), Bytes::from("asdf")))).into_iter());

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
            let stream_id = AccessControlList(vec![
                StandardAccessControlEntry::UserName("russell".into()).into(),
                StandardAccessControlEntry::ResourceName(format!("{i}")).into(),
            ])
            .to_string();

            let recvr = SrtSocket::builder()
                .call("127.0.0.1:2000", Some(stream_id.as_str()))
                .await;

            if i >= 5 {
                let err = recvr.unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
                assert_eq!(
                    err.get_ref().map(|e| e.downcast_ref::<ConnectionReject>()),
                    Some(Some(&ConnectionReject::Rejected(
                        ServerRejectReason::BadRequest.into()
                    )))
                );
            } else {
                let mut recvr = recvr.unwrap();

                info!("Created connection");

                let first = recvr.next().await;
                assert_matches!(first, Some(Ok((_, b))) if b == "asdf", "sockid={:?}", recvr.settings().local_sockid);
                let second = recvr.next().await;
                assert_matches!(second, None);

                info!("Connection done");
            }
        }));
    }

    // close the multiplex server when all is done
    try_join_all(join_handles).await.unwrap();
    info!("all finished");
    server.close().await;
    listener.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn set_password() {
    let (mut server, mut incoming) = SrtListener::builder().bind(2001).await.unwrap();

    let listener = tokio::spawn(async move {
        while let Some(request) = incoming.incoming().next().await {
            let passphrase = request.stream_id().unwrap().as_str().into();

            if let Ok(mut sender) = request
                .accept(Some(KeySettings {
                    key_size: KeySize::AES128,
                    passphrase,
                }))
                .await
            {
                let mut stream =
                    stream::iter(Some(Ok((Instant::now(), Bytes::from("asdf")))).into_iter());

                tokio::spawn(async move {
                    sender.send_all(&mut stream).await.unwrap();
                    sender.close().await.unwrap();
                    info!("Sender finished");
                });
            }
        }
    });

    // match
    SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:2001", Some("password123"))
        .await
        .unwrap()
        .close()
        .await
        .unwrap();

    // match
    SrtSocket::builder()
        .encryption(16, "password128")
        .call("127.0.0.1:2001", Some("password128"))
        .await
        .unwrap()
        .close()
        .await
        .unwrap();

    // mismatch
    let err = SrtSocket::builder()
        .encryption(16, "password128")
        .call("127.0.0.1:2001", Some("password817"))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(
        err.get_ref().map(|e| e.downcast_ref::<ConnectionReject>()),
        Some(Some(&ConnectionReject::Rejected(
            CoreRejectReason::BadSecret.into()
        )))
    );

    server.close().await;
    listener.await.unwrap();
}

#[tokio::test]
async fn key_size() {
    let (mut server, mut incoming) = SrtListener::builder().bind(2001).await.unwrap();

    let listener = tokio::spawn(async move {
        while let Some(request) = incoming.incoming().next().await {
            let key_size = request.key_size();
            let passphrase = request.stream_id().unwrap().as_str().into();

            if let Ok(mut sender) = request
                .accept(Some(KeySettings {
                    key_size,
                    passphrase,
                }))
                .await
            {
                let mut stream =
                    stream::iter(Some(Ok((Instant::now(), Bytes::from("asdf")))).into_iter());

                tokio::spawn(async move {
                    sender.send_all(&mut stream).await.unwrap();
                    sender.close().await.unwrap();
                    info!("Sender finished");
                });
            }
        }
    });

    for key_size_bytes in [0, 16, 24, 32] {
        SrtSocket::builder()
            .encryption(key_size_bytes, "password128")
            .call("127.0.0.1:2001", Some("password128"))
            .await
            .unwrap()
            .close()
            .await
            .expect("server should use the advertised key size");
    }

    server.close().await;
    listener.await.unwrap();
}
