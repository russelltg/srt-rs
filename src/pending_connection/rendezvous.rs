use std::net::SocketAddr;

use failure::Error;
use futures::prelude::*;

use connected::Connected;
use Packet;

pub struct Rendezvous<T> {
    _local_public: SocketAddr,
    _remote_public: SocketAddr,
    _sock: T,
}

impl<T> Rendezvous<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(_sock: T, _local_public: SocketAddr, _remote_public: SocketAddr) -> Rendezvous<T> {
        Rendezvous {
            _sock,
            _local_public,
            _remote_public,
        }
    }
}

impl<T> Future for Rendezvous<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        unimplemented!()
    }
}
