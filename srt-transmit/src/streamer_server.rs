use std::{
    io::{self, ErrorKind},
    pin::Pin,
    sync::mpsc::TryRecvError,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bus::{Bus, BusReader};
use bytes::Bytes;
use futures::{channel::mpsc, select, sink::Sink, FutureExt, SinkExt, StreamExt};
use tokio::time::sleep;

use srt_tokio::{
    options::{ListenerOptions, Valid},
    ConnectionRequest, SrtListener, SrtSocket,
};

// Bus is the best concurrent pub/sub primitive so far in Rust. It is lock free, bounded, low
// allocation, but it is just not async, yet. Also, the receiver instances (i.e. subscriber) can't
// be directly cloned either, so it is awkward to use as a replacement for a typical channel. Since
// a reference to the Bus is necessary in order to construct new subscribers, an mpsc channel is
// placed in front of the Bus and a tokio task is spawned to both read from this channel and then
// push it to the bus as well as accepting new connection requests and spawning new tasks that read
// from a per connection Bus subscriber, sending the data to the new connection socket.
//
// TODO: get rid of mpsc channel and consider writing a legit Sink wrapper for Bus, or find an
//  alternative pub/sub bus
pub struct StreamerServer(mpsc::Sender<(Instant, Bytes)>);

impl StreamerServer {
    pub async fn bind(options: Valid<ListenerOptions>) -> Result<Self, io::Error> {
        let (sender, receiver) = mpsc::channel(100);
        let listener = SrtListener::bind(options).await?;
        tokio::spawn(async move {
            Self::run_receive_loop(listener, receiver).await;
        });

        Ok(StreamerServer(sender))
    }

    pub async fn run_receive_loop(
        mut listener: SrtListener,
        receiver: mpsc::Receiver<(Instant, Bytes)>,
    ) {
        let mut incoming = listener.incoming().fuse();
        let mut receiver = receiver.fuse();
        let mut bus = Bus::new(10_000);

        loop {
            enum Select {
                Request(Option<ConnectionRequest>),
                Data(Option<(Instant, Bytes)>),
                Timer,
            }

            use Select::*;
            let selection = select! (
                request = incoming.next() => Request(request),
                data = receiver.next() => Data(data),
                _ = sleep(Duration::from_micros(1)).fuse() => Timer,
            );

            match selection {
                Request(Some(request)) => {
                    let sender = request.accept(None).await.unwrap();
                    let input = bus.add_rx();
                    tokio::spawn(async move {
                        Self::run_send_loop(sender, input).await;
                    });
                }
                Data(Some(data)) => {
                    if let Err(data) = bus.try_broadcast(data) {
                        let mut pending_data = Some(data);
                        while let Some(data) = pending_data.take() {
                            tokio::time::sleep(Duration::from_micros(1)).await;
                            if let Err(data) = bus.try_broadcast(data) {
                                pending_data = Some(data);
                            }
                        }
                    }
                }
                Timer => {}
                Data(None) | Request(None) => break,
            }
        }
    }

    async fn run_send_loop(mut sender: SrtSocket, mut input: BusReader<(Instant, Bytes)>) {
        loop {
            match input.try_recv() {
                Ok(val) => {
                    if sender.send(val).await.is_err() {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_micros(1)).await;
                }
                Err(TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        let _ = sender.close().await;
    }
}

impl Sink<(Instant, Bytes)> for StreamerServer {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.0
            .poll_ready(cx)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))
    }

    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        self.0
            .start_send(item)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use anyhow::Result;
    use bytes::Bytes;
    use futures::{future::join_all, SinkExt, StreamExt};
    use log::info;
    use srt_tokio::SrtSocket;

    use super::*;

    #[tokio::test]
    async fn multiplexer() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        let listener = tokio::spawn(async {
            let options = ListenerOptions::new(2000).unwrap();
            let mut server = StreamerServer::bind(options).await.unwrap();
            let end = Instant::now() + Duration::from_secs(1);
            while end > Instant::now() {
                server
                    .send((Instant::now(), Bytes::from("asdf")))
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
                    assert_eq!(data.unwrap().1, "asdf");
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
