use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;

use connected::Connected;
use packet::Packet;

pub struct Connect<T> {
    remote: SocketAddr,
    sock: T,
}

impl<T> Connect<T> {
    pub fn new(sock: T, remote: SocketAddr) -> Connect<T> {
        Connect { sock, remote }
    }
}

impl<T> Future for Connect<T>
    where T: Stream<Item=(Packet, SocketAddr), Error=Error> +
    Sink<SinkItem=(Packet, SocketAddr), SinkError=Error> {
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        unimplemented!()
    }
}
