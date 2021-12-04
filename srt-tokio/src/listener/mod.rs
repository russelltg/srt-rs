mod request;
mod state;

pub use request::ConnectionRequest;

use std::io;

use futures::{channel::mpsc, prelude::*};
use srt_protocol::settings::ConnInitSettings;
use tokio::{net::ToSocketAddrs, task::JoinHandle};

use crate::watch;

use super::net::PacketSocket;

pub use srt_protocol::listener::ListenerStatistics;

pub struct SrtListener {
    settings: ConnInitSettings,
    request_receiver: mpsc::Receiver<ConnectionRequest>,
    statistics_receiver: watch::Receiver<ListenerStatistics>,
    _task: JoinHandle<()>,
}

impl SrtListener {
    pub async fn bind<A: ToSocketAddrs>(address: A) -> Result<Self, io::Error> {
        use state::SrtListenerState;

        let settings = ConnInitSettings::default();
        let (request_sender, request_receiver) = mpsc::channel(100);
        let (statistics_sender, statistics_receiver) = watch::channel();
        let socket = PacketSocket::bind(address, 1024 * 1024).await?;
        let state = SrtListenerState::new(socket, request_sender, statistics_sender);
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
mod test {
    use std::time::Instant;

    use anyhow::Result;
    use bytes::Bytes;
    use futures::{channel::oneshot, future::join_all, prelude::*};
    use log::{debug, info};

    use crate::{ConnectionRequest, ListenerStatistics, SrtListener, SrtSocketBuilder};

    #[tokio::test]
    async fn srt_listener() -> Result<()> {
        #[derive(Debug)]
        enum Select {
            Connection(Option<ConnectionRequest>),
            Statistics(Option<ListenerStatistics>),
            Finished,
        }

        let _ = pretty_env_logger::try_init();

        let (finished_send, finished_recv) = oneshot::channel();

        let listener = tokio::spawn(async {
            let mut server = SrtListener::bind("127.0.0.1:2000").await.unwrap();
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
                        let mut sender = request.accept(None).await.unwrap();

                        let mut stream = stream::iter(
                            Some(Ok((Instant::now(), Bytes::from("asdf")))).into_iter(),
                        );

                        tokio::spawn(async move {
                            sender.send_all(&mut stream).await.unwrap();
                            sender.close().await.unwrap();
                            info!("Sender finished");
                        });
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
        listener.await?;
        Ok(())
    }
}
