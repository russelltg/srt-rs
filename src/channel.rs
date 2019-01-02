use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc::{self, Receiver, Sender};
use futures::{Poll, StartSend};

use failure::Error;

pub struct Channel<T> {
    sender: Sender<T>,
    recvr: Receiver<T>,
}

impl<T: Send + Sync> Stream for Channel<T> {
    type Item = T;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(self.recvr.poll().unwrap())
    }
}

impl<T: Send + Sync + 'static> Sink for Channel<T> {
    type SinkItem = T;
    type SinkError = Error;

    fn start_send(&mut self, item: T) -> StartSend<Self::SinkItem, Self::SinkError> {
        Ok(self.sender.start_send(item)?)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(self.sender.poll_complete()?)
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        Ok(self.sender.close()?)
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
