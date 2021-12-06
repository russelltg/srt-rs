mod builder;
mod session;
mod state;

use std::{io, sync::Arc};

use futures::{channel::mpsc, prelude::*};
use srt_protocol::settings::ConnInitSettings;
use tokio::{net::UdpSocket, task::JoinHandle};

use super::{net::PacketSocket, options::*, watch};

pub use builder::NewSrtListener;
pub use session::ConnectionRequest;
pub use srt_protocol::statistics::ListenerStatistics;

pub struct SrtListener {
    settings: ConnInitSettings,
    request_receiver: mpsc::Receiver<ConnectionRequest>,
    statistics_receiver: watch::Receiver<ListenerStatistics>,
    _task: JoinHandle<()>,
}

impl SrtListener {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> NewSrtListener {
        NewSrtListener::default()
    }

    pub async fn bind(options: Valid<ListenerOptions>) -> Result<Self, io::Error> {
        let socket = UdpSocket::bind(options.socket.connect.local).await?;
        Self::bind_with_socket(options, socket).await
    }

    pub async fn bind_with_socket(
        options: Valid<ListenerOptions>,
        socket: UdpSocket,
    ) -> Result<Self, io::Error> {
        use state::SrtListenerState;
        let socket_options = options.into_value().socket;
        let local_address = socket.local_addr()?;
        let socket = PacketSocket::from_socket(Arc::new(socket), 1024 * 1024);
        let settings = ConnInitSettings::from(socket_options);
        let (request_sender, request_receiver) = mpsc::channel(100);
        let (statistics_sender, statistics_receiver) = watch::channel();
        let state = SrtListenerState::new(
            socket,
            local_address,
            settings.clone(),
            request_sender,
            statistics_sender,
        );
        let task = tokio::spawn(async move {
            state.run_loop().await;
        });

        Ok(Self {
            settings,
            request_receiver,
            statistics_receiver,
            _task: task,
        })
    }

    pub fn settings(&self) -> &ConnInitSettings {
        &self.settings
    }

    pub fn statistics(&mut self) -> &mut (impl Stream<Item = ListenerStatistics> + Clone) {
        &mut self.statistics_receiver
    }

    pub fn incoming(&mut self) -> &mut impl Stream<Item = ConnectionRequest> {
        &mut self.request_receiver
    }
}

impl Drop for SrtListener {
    fn drop(&mut self) {
        // TODO: we probably need to use a std::sync primitive to block until closed
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use anyhow::Result;
    use bytes::Bytes;
    use futures::{channel::oneshot, future::join_all, prelude::*};
    use log::{debug, info};

    use crate::{ConnectionRequest, ListenerStatistics, SrtListener, SrtSocket};

    #[tokio::test]
    async fn accept_reject() -> Result<()> {
        #[derive(Debug)]
        enum Select {
            Connection(Option<ConnectionRequest>),
            Statistics(Option<ListenerStatistics>),
            Finished,
        }

        let _ = pretty_env_logger::try_init();

        let (finished_send, finished_recv) = oneshot::channel();

        let listener = tokio::spawn(async {
            let mut server = SrtListener::new().bind("127.0.0.1:4001").await.unwrap();
            let mut statistics = server.statistics().clone().fuse();

            let mut incoming = server.incoming().fuse();
            let mut fused_finish = finished_recv.fuse();
            loop {
                let selection = futures::select!(
                    request = incoming.next() => Select::Connection(request),
                    stats = statistics.next() => Select::Statistics(stats),
                    _ = fused_finish => Select::Finished,
                );
                match selection {
                    Select::Connection(Some(request)) => {
                        let stream_id = request.stream_id().unwrap();
                        if stream_id.eq(&"reject".into()) {
                            let _ = request.reject(42).await.unwrap();
                        } else {
                            let mut sender = request.accept(None).await.unwrap();
                            let mut stream = stream::iter(
                                Some(Ok((Instant::now(), Bytes::from("hello")))).into_iter(),
                            );
                            tokio::spawn(async move {
                                sender.send_all(&mut stream).await.unwrap();
                                sender.close().await.unwrap();
                                info!("Sent");
                            });
                        }
                    }
                    Select::Statistics(Some(stats)) => debug!("{:?}", stats),
                    _ => {
                        break;
                    }
                }
            }
        });

        // connect 10 clients to it
        let mut join_handles = vec![];
        for i in 0..10 {
            join_handles.push(tokio::spawn(async move {
                info!("Calling: {}", i);
                let address = "127.0.0.1:4001";
                if i % 2 > 0 {
                    let result = SrtSocket::new().call(address, Some("reject")).await;
                    assert!(result.is_err());
                    debug!("Rejected: {}", i);
                } else {
                    let stream_id = format!("{}", i).to_string();
                    let mut receiver = SrtSocket::new().call(address, Some(&stream_id)).await.unwrap();
                    info!("Accepted: {}", i);
                    let first = receiver.next().await;
                    assert_eq!(first.unwrap().unwrap().1, "hello");
                    let second = receiver.next().await;
                    assert!(second.is_none());
                    info!("Received: {}", i);
                }
            }));
        }

        // close the multiplex server when all is done
        join_all(join_handles).await;
        info!("all finished");
        finished_send.send(()).unwrap();
        listener.await?;
        Ok(())
    }


    #[tokio::test]
    async fn accept_reject_encryption() -> Result<()> {
        #[derive(Debug)]
        enum Select {
            Connection(Option<ConnectionRequest>),
            Statistics(Option<ListenerStatistics>),
            Finished,
        }

        let _ = pretty_env_logger::try_init();

        let (finished_send, finished_recv) = oneshot::channel();

        let listener = tokio::spawn(async {
            let mut server = SrtListener::new()
                .encryption(0, "super secret passcode")
                .bind("127.0.0.1:4002").await.unwrap();
            let mut statistics = server.statistics().clone().fuse();

            let mut incoming = server.incoming().fuse();
            let mut fused_finish = finished_recv.fuse();
            loop {
                let selection = futures::select!(
                    request = incoming.next() => Select::Connection(request),
                    stats = statistics.next() => Select::Statistics(stats),
                    _ = fused_finish => Select::Finished,
                );
                match selection {
                    Select::Connection(Some(request)) => {
                        let stream_id = request.stream_id().expect("stream_id");
                        if stream_id.eq(&"reject".into()) {
                            let _ = request.reject(42).await.expect("reject");
                        } else {
                            let mut sender = request.accept(None).await.expect("accept");
                            let mut stream = stream::iter(
                                Some(Ok((Instant::now(), Bytes::from("hello")))).into_iter(),
                            );
                            tokio::spawn(async move {
                                sender.send_all(&mut stream).await.expect("send_all");
                                sender.close().await.expect("close");
                                info!("Sent");
                            });
                        }
                    }
                    Select::Statistics(Some(stats)) => debug!("{:?}", stats),
                    _ => {
                        break;
                    }
                }
            }
        });

        // connect 10 clients to it
        let mut join_handles = vec![];
        for i in 0..10 {
            join_handles.push(tokio::spawn(async move {
                info!("Calling: {}", i);
                let address = "127.0.0.1:4002";
                if i % 2 == 0 {
                    let result = SrtSocket::new().call(address, Some("reject")).await;
                    assert!(result.is_err());
                    info!("Rejected: {}", i);
                } else {
                    let stream_id = format!("{}", i).to_string();
                    let mut receiver = SrtSocket::new()
                        .encryption(0, "super secret passcode")
                        .call(address, Some(&stream_id)).await.expect("call");
                    info!("Accepted: {}", i);
                    let first = receiver.next().await;
                    assert_eq!(first.expect("next error").expect("next no data").1, "hello");
                    let second = receiver.next().await;
                    assert!(second.is_none());
                    info!("Received: {}", i);
                }
            }));
        }

        // close the multiplex server when all is done
        join_all(join_handles).await;
        info!("all finished");
        finished_send.send(()).unwrap();
        listener.await?;
        Ok(())
    }
}
