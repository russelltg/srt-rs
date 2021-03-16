use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, time::Instant};

use futures::channel::mpsc;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::{ready, SinkExt, StreamExt};

use bytes::Bytes;

use crate::{Connection, SrtSocket, tokio::create_bidrectional_srt};
use srt_protocol::NullEventReceiver;

type BoxConnStream = Pin<Box<dyn Stream<Item = Result<SrtSocket, io::Error>> + Send>>;
pub struct StreamerServer {
    server: BoxConnStream,
    channels: Vec<mpsc::Sender<(Instant, Bytes)>>,
}

impl StreamerServer {
    pub fn new(server: impl Stream<Item = Result<SrtSocket, io::Error>> + Send + 'static) -> Self {
        StreamerServer {
            server: server.boxed(),
            channels: vec![], // TODO: research lengths
        }
    }
}

impl Sink<(Instant, Bytes)> for StreamerServer {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut i = 0;
        while i != self.channels.len() {
            if ready!(Pin::new(&mut self.channels[i]).poll_ready(cx)).is_err() {
                self.channels.remove(i);
            } else {
                i += 1;
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut i = 0;
        while i != self.channels.len() {
            if ready!(Pin::new(&mut self.channels[i]).poll_close(cx)).is_err() {
                self.channels.remove(i);
            } else {
                i += 1;
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), io::Error> {
        let mut i = 0;
        while i != self.channels.len() {
            if self.channels[i].start_send(item.clone()).is_err() {
                self.channels.remove(i);
            } else {
                i += 1;
            }
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut i = 0;
        while i != self.channels.len() {
            if let Poll::Ready(Err(_)) = Pin::new(&mut self.channels[i]).poll_flush(cx) {
                self.channels.remove(i);
            } else {
                i += 1;
            }
        }

        loop {
            let mut sender = ready!(Pin::new(&mut self.server).poll_next(cx))
                .expect("Multiplexer stream ended, strange")
                .expect("Multiplex server return Err");

            let (tx, rx) = mpsc::channel(100);

            self.channels.push(tx);

            // TODO: remove from the channel list when finished
            tokio::spawn(async move {
                sender.send_all(&mut rx.map(Ok)).await.unwrap();
                sender.close().await.unwrap();
            });
        }
    }
}
