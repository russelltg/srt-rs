pub use srt_protocol::statistics::SocketStatistics;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use tokio::sync::watch::Receiver;
use tokio_stream::wrappers::WatchStream;

#[derive(Debug)]
pub struct SrtSocketStatistics(Receiver<SocketStatistics>, WatchStream<SocketStatistics>);

impl Clone for SrtSocketStatistics {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.0.clone().into())
    }
}

impl Stream for SrtSocketStatistics {
    type Item = SocketStatistics;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().1).poll_next(cx)
    }
}

impl SrtSocketStatistics {
    pub(crate) fn new(receiver: Receiver<SocketStatistics>) -> Self {
        Self(receiver.clone(), receiver.into())
    }
}
