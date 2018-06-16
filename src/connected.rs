use {
    failure::Error, futures::prelude::*, receiver::Receiver, sender::Sender, std::net::SocketAddr,
    CongestCtrl, ConnectionSettings, DefaultCongestCtrl, Packet,
};

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

    pub fn sender(self) -> Sender<T, DefaultCongestCtrl> {
        self.sender_with_cc(DefaultCongestCtrl::new())
    }
    pub fn sender_with_cc<CC: CongestCtrl>(self, cc: CC) -> Sender<T, CC> {
        Sender::new(self.socket, cc, self.settings)
    }
}
