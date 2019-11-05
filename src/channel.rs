use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{self, Receiver, Sender};
use futures::sink::Sink;
use futures::stream::Stream;

use failure::Error;

pub struct Channel<T> {
    sender: Sender<T>,
    recvr: Receiver<T>,
}

impl<T: Send + Sync> Stream for Channel<T> {
    type Item = Result<T, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(futures::ready!(Pin::new(&mut self.recvr).poll_next(cx)).map(Ok))
    }
}

impl<T: Send + Sync + 'static> Sink<T> for Channel<T> {
    type Error = Error;

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Error> {
        Ok(Pin::new(&mut self.sender).start_send(item)?)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(futures::ready!(Pin::new(&mut self.sender).poll_ready(cx)).map_err(Error::from))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(futures::ready!(Pin::new(&mut self.sender).poll_flush(cx)).map_err(Error::from))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(futures::ready!(Pin::new(&mut self.sender).poll_close(cx)).map_err(Error::from))
    }
}

impl<T> Channel<T> {
    pub fn channel(buffer: usize) -> (Channel<T>, Channel<T>) {
        let (s1, r1) = mpsc::channel(buffer);
        let (s2, r2) = mpsc::channel(buffer);

        (
            Channel {
                sender: s1,
                recvr: r2,
            },
            Channel {
                sender: s2,
                recvr: r1,
            },
        )
    }
}
