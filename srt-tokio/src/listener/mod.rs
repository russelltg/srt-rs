mod builder;
mod session;
mod state;

use std::{io, sync::Arc};

use futures::{channel::mpsc, prelude::*};
use srt_protocol::settings::ConnInitSettings;
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle};

use crate::net::bind_socket;

use super::{net::PacketSocket, options::*, watch};

pub use builder::SrtListenerBuilder;
pub use session::ConnectionRequest;
pub use srt_protocol::statistics::ListenerStatistics;

pub struct SrtListener {
    settings: ConnInitSettings,
    statistics_receiver: watch::Receiver<ListenerStatistics>,
    close_req: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

pub struct SrtIncoming {
    request_receiver: mpsc::Receiver<ConnectionRequest>,
}

impl SrtListener {
    pub fn builder() -> SrtListenerBuilder {
        SrtListenerBuilder::default()
    }

    pub async fn bind(options: Valid<ListenerOptions>) -> Result<(Self, SrtIncoming), io::Error> {
        let socket = bind_socket(&options.socket).await?;
        Self::bind_with_socket(options, socket).await
    }

    pub async fn bind_with_socket(
        options: Valid<ListenerOptions>,
        socket: UdpSocket,
    ) -> Result<(Self, SrtIncoming), io::Error> {
        use state::SrtListenerState;
        let socket_options = options.into_value().socket;
        let local_address = socket.local_addr()?;
        let socket = PacketSocket::from_socket(Arc::new(socket), 1024 * 1024);
        let settings = ConnInitSettings::from(socket_options);
        let (close_req, close_resp) = oneshot::channel();
        let (request_sender, request_receiver) = mpsc::channel(100);
        let (statistics_sender, statistics_receiver) = watch::channel();
        let state = SrtListenerState::new(
            socket,
            local_address,
            settings.clone(),
            request_sender,
            statistics_sender,
            close_resp,
        );
        let task = tokio::spawn(async move {
            state.run_loop().await;
        });
        Ok((
            Self {
                settings,
                statistics_receiver,
                close_req: Some(close_req),
                task,
            },
            SrtIncoming { request_receiver },
        ))
    }

    pub fn settings(&self) -> &ConnInitSettings {
        &self.settings
    }

    pub fn statistics(&mut self) -> &mut (impl Stream<Item = ListenerStatistics> + Clone) {
        &mut self.statistics_receiver
    }

    pub async fn close(&mut self) {
        let _ = self.close_req.take().unwrap().send(());
        (&mut self.task).await.unwrap();
    }
}

impl SrtIncoming {
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
    use std::time::{Duration, Instant};

    use anyhow::Result;
    use bytes::Bytes;
    use futures::{channel::oneshot, future::join_all, prelude::*};
    use log::{debug, info};

    use crate::{access::*, SrtSocket};

    use super::*;

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
            let (mut server, mut incoming) =
                SrtListener::builder().bind("127.0.0.1:4001").await.unwrap();
            let mut statistics = server.statistics().clone().fuse();

            let mut incoming = incoming.incoming().fuse();
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
                            let _ = request.reject(RejectReason::User(42)).await.unwrap();
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
                    let result = SrtSocket::builder().call(address, Some("reject")).await;
                    assert!(result.is_err());
                    debug!("Rejected: {}", i);
                } else {
                    let stream_id = format!("{}", i).to_string();
                    let mut receiver = SrtSocket::builder()
                        .call(address, Some(&stream_id))
                        .await
                        .unwrap();
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
            let (mut server, mut incoming) = SrtListener::builder()
                .encryption(0, "super secret passcode")
                .bind("127.0.0.1:4002")
                .await
                .unwrap();
            let mut statistics = server.statistics().clone().fuse();

            let mut incoming = incoming.incoming().fuse();
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
                            let _ = request
                                .reject(RejectReason::User(42))
                                .await
                                .expect("reject");
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
                    let result = SrtSocket::builder().call(address, Some("reject")).await;
                    assert!(result.is_err());
                    info!("Rejected: {}", i);
                } else {
                    let stream_id = format!("{}", i).to_string();
                    let mut receiver = SrtSocket::builder()
                        .encryption(0, "super secret passcode")
                        .call(address, Some(&stream_id))
                        .await
                        .expect("call");
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

    #[tokio::test]
    async fn multiplex_timeout() {
        use bytes::Bytes;
        use futures::{stream, SinkExt, StreamExt};
        use log::info;
        use tokio::time::sleep;

        use srt_protocol::options::*;

        async fn run_listener() -> Result<(), io::Error> {
            let port = 4444;
            let (_binding, mut incoming) = SrtListener::builder()
                .with(Sender {
                    drop_delay: Duration::from_secs(20),
                    peer_latency: Duration::from_secs(1),
                    buffer_size: ByteCount(8192 * 100),
                    ..Default::default()
                })
                .bind("127.0.0.1:4444")
                .await
                .unwrap();

            info!("SRT Multiplex Server is listening on port: {}", port);
            while let Some(request) = incoming.incoming().next().await {
                let mut srt_socket = request.accept(None).await.unwrap();

                tokio::spawn(async move {
                    let client_desc = format!(
                        "(ip_port: {}, sockid: {})",
                        srt_socket.settings().remote,
                        srt_socket.settings().remote_sockid.0
                    );

                    info!("New client connected: {}", client_desc);

                    let longer_than_peer_timeout = Duration::from_secs(7);
                    let start = Instant::now();
                    let mut stream = stream::unfold(0, |count| async move {
                        let res = Ok((Instant::now(), Bytes::copy_from_slice(&[0; 1316])));
                        sleep(Duration::from_millis(5)).await;
                        if start.elapsed() > longer_than_peer_timeout {
                            return None;
                        }
                        Some((res, count))
                    })
                    .boxed();

                    if let Err(e) = srt_socket.send_all(&mut stream).await {
                        info!("Send to client: {} error: {:?}", client_desc, e);
                    }
                    info!("Client {} disconnected", client_desc);

                    start.elapsed().as_secs() as i32
                });
            }
            Ok(())
        }

        async fn run_receiver(id: u32) -> Result<i32, io::Error> {
            let mut srt_socket = SrtSocket::builder()
                .with(Receiver {
                    buffer_size: ByteCount(8192 * 100),
                    latency: Duration::from_secs(1),
                    ..Default::default()
                })
                .call("127.0.0.1:4444", None)
                .await
                .unwrap();

            info!("Client {} connection opened", id);

            let mut count = 1;
            let start = Instant::now();
            while let Some((_instant, _bytes)) = srt_socket.try_next().await? {
                if count % 200 == 0 {
                    info!("{} received {:?} packets", id, count);
                }
                count += 1;
            }
            info!("Client {} received {:?} packets", id, count);
            info!("Client {} connection closed", id);

            Ok(start.elapsed().as_secs() as i32)
        }

        let _listener_handle = tokio::spawn(run_listener());
        let join_handles = [
            tokio::spawn(run_receiver(1)),
            tokio::spawn(run_receiver(2)),
            tokio::spawn(run_receiver(3)),
        ];
        let min_elapsed_seconds = join_all(join_handles)
            .await
            .into_iter()
            .map(|r| r.unwrap().unwrap_or_default())
            .min()
            .unwrap_or_default();

        // clients should have still received data well past the default peer timout
        assert!(min_elapsed_seconds > 5);
    }
}
