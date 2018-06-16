use Sender;

use {
    bytes::Bytes, futures::prelude::*, serde_json,
    std::{
        net::SocketAddr, ops::{Deref, DerefMut}, time::Duration,
    },
    CongestCtrl, Packet,
	failure::Error,
};

pub struct StatsPrinterSender<T, CC> {
    sender: Sender<T, CC>,
}

impl<T, CC> StatsPrinterSender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestCtrl,
{
    pub fn new(mut sender: Sender<T, CC>, interval: Duration) -> StatsPrinterSender<T, CC> {
        sender.set_stats_interval(interval);

        StatsPrinterSender { sender }
    }
}

impl<T, CC> Deref for StatsPrinterSender<T, CC> {
    type Target = Sender<T, CC>;
    fn deref(&self) -> &Sender<T, CC> {
        &self.sender
    }
}

impl<T, CC> DerefMut for StatsPrinterSender<T, CC> {
    fn deref_mut(&mut self) -> &mut Sender<T, CC> {
        &mut self.sender
    }
}

impl<T, CC> Sink for StatsPrinterSender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestCtrl,
{
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {
        self.sender.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        if let Ok(Async::Ready(Some(stats))) = self.sender.poll() {
            println!("{},", serde_json::to_string(&stats).unwrap());
        }

        self.sender.poll_complete()
    }
}
