use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures::channel::mpsc;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::{ready, SinkExt, StreamExt};

use bytes::Bytes;

use failure::Error;

use crate::{Connection, PackChan, SenderSink, SrtCongestCtrl};

type BoxConnStream = Pin<Box<dyn Stream<Item = Result<(Connection, PackChan), Error>> + Send>>;
pub struct StreamerServer {
    server: BoxConnStream,
    channels: Vec<mpsc::Sender<(Instant, Bytes)>>,
}

impl StreamerServer {
    pub fn new(
        server: impl Stream<Item = Result<(Connection, PackChan), Error>> + Send + 'static,
    ) -> Self {
        StreamerServer {
            server: server.boxed(),
            channels: vec![], // TODO: research lengths
        }
    }
}

impl Sink<(Instant, Bytes)> for StreamerServer {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        for i in &mut self.channels {
            if let Err(e) = ready!(i.poll_ready(cx)) {
                return Poll::Ready(Err(Error::from(e)));
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        for i in &mut self.channels {
            if let Err(e) = ready!(Pin::new(i).poll_close(cx)) {
                return Poll::Ready(Err(Error::from(e)));
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Error> {
        for i in &mut self.channels {
            i.start_send(item.clone())?;
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        for i in &mut self.channels {
            let _ = Pin::new(i).poll_flush(cx)?;
        }

        loop {
            let (conn, chan) = ready!(Pin::new(&mut self.server).poll_next(cx))
                .expect("Multiplexer stream ended, strange")
                .expect("Multiplex server return Err");

            let mut sender = SenderSink::new(chan, SrtCongestCtrl, conn.settings, conn.handshake);

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
