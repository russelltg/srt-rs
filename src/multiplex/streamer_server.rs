use std::time::Instant;

use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::{try_ready, AsyncSink, Poll, StartSend};

use bytes::Bytes;

use failure::{format_err, Error};

use log::warn;

use crate::MultiplexServer;

pub struct StreamerServer {
    server: MultiplexServer,
    channels: Vec<mpsc::Sender<(Instant, Bytes)>>,
}

impl StreamerServer {
    pub fn new(server: MultiplexServer) -> Self {
        StreamerServer {
            server,
            channels: vec![], // TODO: research lengths
        }
    }
}

impl Sink for StreamerServer {
    type SinkItem = (Instant, Bytes);
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        for i in &mut self.channels {
            i.start_send(item.clone())?;
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        for i in &mut self.channels {
            i.poll_complete()?;
        }

        loop {
            let sender = try_ready!(self.server.poll())
                .expect("Multiplexer stream ended, strange")
                .sender();

            let (tx, rx) = mpsc::channel(100);

            self.channels.push(tx);

            // TODO: remove from the channel list when finished
            tokio::spawn(
                rx.map_err(|_| format_err!(""))
                    .forward(sender)
                    .map_err(|e| warn!("{}", e))
                    .map(|_| ()),
            );
        }
    }
}
