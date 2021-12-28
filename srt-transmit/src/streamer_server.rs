use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use bytes::Bytes;
use futures::{channel::oneshot, select, sink::Sink, FutureExt, SinkExt, StreamExt};
use log::warn;
use tokio::sync::broadcast::{self, error::*};

use srt_tokio::{
    options::{ListenerOptions, Valid},
    SrtIncoming, SrtListener, SrtSocket,
};

pub struct StreamerServer(broadcast::Sender<(Instant, Bytes)>, oneshot::Sender<()>);

impl StreamerServer {
    pub async fn bind(options: Valid<ListenerOptions>) -> Result<Self, io::Error> {
        let (broadcast_sender, broadcast_receiver) = broadcast::channel(10_000);
        let (cancel_sender, cancel_receiver) = oneshot::channel();

        let (listener, incoming) = SrtListener::bind(options).await?;
        let server = broadcast_sender.clone();
        tokio::spawn(async move {
            Self::run_receive_loop(
                listener,
                incoming,
                cancel_receiver,
                broadcast_sender,
                broadcast_receiver,
            )
            .await;
        });

        Ok(StreamerServer(server, cancel_sender))
    }

    pub async fn run_receive_loop(
        _listener: SrtListener,
        mut incoming: SrtIncoming,
        cancel: oneshot::Receiver<()>,
        broadcast_sender: broadcast::Sender<(Instant, Bytes)>,
        _broadcast_receiver: broadcast::Receiver<(Instant, Bytes)>,
    ) {
        let mut incoming = incoming.incoming().fuse();
        let mut cancel = cancel.fuse();
        while let Some(request) = select!(
                    _ = cancel => return,
                    result = incoming.next() => result)
        {
            let sender = request.accept(None).await.unwrap();
            let input = broadcast_sender.subscribe();
            let run_send_loop = Self::run_send_loop(sender, input);
            tokio::spawn(run_send_loop);
        }
    }

    async fn run_send_loop(
        mut sender: SrtSocket,
        mut input: broadcast::Receiver<(Instant, Bytes)>,
    ) {
        loop {
            match input.recv().await {
                Ok(data) => {
                    if sender.send(data).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => {
                    break;
                }
                Err(RecvError::Lagged(dropped)) => {
                    warn!("Stream server dropped packets {}", dropped)
                }
            }
        }
        let _ = sender.close().await;
    }
}

impl Sink<(Instant, Bytes)> for StreamerServer {
    type Error = SendError<(Instant, Bytes)>;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        let _ = self.0.send(item)?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::SrtSocket;
    use anyhow::Result;
    use bytes::Bytes;
    use futures::future::join_all;
    use log::info;
    use tokio::time::sleep;

    use super::*;

    #[tokio::test]
    async fn multiplexer() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        let listener = tokio::spawn(async {
            let options = ListenerOptions::new(2000).unwrap();
            let mut server = StreamerServer::bind(options).await.unwrap();
            let end = Instant::now() + Duration::from_secs(1);
            let mut count = 0;
            while end > Instant::now() {
                count += 1;
                server
                    .send((Instant::now(), Bytes::from(format!("asdf {}", count))))
                    .await
                    .unwrap();
                sleep(Duration::from_millis(10)).await;
            }
            server.close().await.unwrap();
            info!("Sender finished");
        });

        // connect 10 clients to it
        let mut join_handles = vec![];
        for i in 0..3 {
            join_handles.push(tokio::spawn(async move {
                let mut recvr = SrtSocket::builder()
                    .call("127.0.0.1:2000", None)
                    .await
                    .unwrap();

                info!("Created connection {}", i);

                while let Some(data) = recvr.next().await {
                    info!("Data {}: {:?}", i, data);
                    assert!(data.unwrap().1.starts_with("asdf".as_bytes()));
                }

                info!("Receiving done {}", i);
            }));
        }

        // close the multiplex server when all is done
        join_all(join_handles).await;
        info!("all finished");
        listener.await?;
        Ok(())
    }
}
