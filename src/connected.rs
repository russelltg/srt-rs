use std::net::SocketAddr;

use failure::Error;
use futures::prelude::*;

// use crate::receiver::Receiver;
// use crate::sender::Sender;
// use crate::{CongestCtrl, ConnectionSettings, Packet, SrtCongestCtrl};
use crate::{ConnectionSettings, Packet};

pub struct Connected<T> {
    socket: T,
    settings: ConnectionSettings,
}

impl<T> Connected<T>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>,
{
    pub fn new(socket: T, settings: ConnectionSettings) -> Connected<T> {
        Connected { socket, settings }
    }

    //     pub fn settings(&self) -> &ConnectionSettings {
    //         &self.settings
    //     }

    //     pub fn receiver(self) -> Receiver<T> {
    //         Receiver::new(self.socket, self.settings)
    //     }

    //     pub fn sender(self) -> Sender<T, SrtCongestCtrl> {
    //         self.sender_with_cc(SrtCongestCtrl)
    //     }
    //     pub fn sender_with_cc<CC: CongestCtrl>(self, cc: CC) -> Sender<T, CC> {
    //         Sender::new(self.socket, cc, self.settings)
    //     }
}
