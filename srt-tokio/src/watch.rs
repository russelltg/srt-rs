use std::{
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use tokio::sync::watch::{self, error::SendError};
use tokio_stream::wrappers::WatchStream;

pub fn channel<T: 'static + Debug + Default + Clone + Send + Sync + Unpin>(
) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = watch::channel(T::default());
    let stream = WatchStream::new(receiver.clone());
    (Sender(sender), Receiver(receiver, stream))
}

#[derive(Debug)]
pub struct Sender<T: 'static + Debug + Default + Clone + Send + Sync + Unpin>(watch::Sender<T>);

impl<T: 'static + Debug + Default + Clone + Send + Sync + Unpin> Sender<T> {
    pub fn send(&self, item: T) -> Result<(), SendError<T>> {
        self.0.send(item)
    }
}

#[derive(Debug)]
pub struct Receiver<T: 'static + Debug + Default + Clone + Send + Sync + Unpin>(
    watch::Receiver<T>,
    WatchStream<T>,
);

impl<T: 'static + Debug + Default + Clone + Send + Sync + Unpin> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        let stream = WatchStream::new(self.0.clone());
        Self(self.0.clone(), stream)
    }
}

impl<T: 'static + Debug + Default + Clone + Send + Sync + Unpin> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().1).poll_next(cx)
    }
}
