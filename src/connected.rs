use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;

use receiver::Receiver;
use sender::Sender;
use ConnectionSettings;
use DefaultSenderCongestionCtrl;
use Packet;

pub struct Connected<T> {
    socket: T,
    settings: ConnectionSettings,
}

impl<T> Connected<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(socket: T, settings: ConnectionSettings) -> Connected<T> {
        Connected { socket, settings }
    }

    pub fn receiver(self) -> Receiver<T> {
        Receiver::new(self.socket, self.settings)
    }

    pub fn sender(self) -> Sender<T, DefaultSenderCongestionCtrl> {
        Sender::new(
            self.socket,
            DefaultSenderCongestionCtrl::new(),
            self.settings,
        )
    }
}
