pub mod connect;
pub mod listen;
pub mod rendezvous;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use failure::Error;
use futures::prelude::*;

use crate::connected::Connected;

use self::connect::Connect;
use self::listen::Listen;
use self::rendezvous::Rendezvous;

use crate::{Packet, SocketID};

pub enum PendingConnection<T> {
    Listen(Listen<T>),
    Rendezvous(Rendezvous<T>),
    Connect(Connect<T>),
}

impl<T> PendingConnection<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn listen(
        sock: T,
        local_socket_id: SocketID,
        tsbpd_latency: Option<Duration>,
    ) -> PendingConnection<T> {
        PendingConnection::Listen(Listen::new(sock, local_socket_id, tsbpd_latency))
    }

    pub fn connect(
        sock: T,
        local_addr: IpAddr,
        remote_addr: SocketAddr,
        local_socket_id: SocketID,
        tsbpd_latency: Option<Duration>,
    ) -> PendingConnection<T> {
        PendingConnection::Connect(Connect::new(
            sock,
            remote_addr,
            local_socket_id,
            local_addr,
            tsbpd_latency,
        ))
    }

    pub fn rendezvous(
        sock: T,
        local_public: SocketAddr,
        remote_public: SocketAddr,
        tsbpd_latency: Option<Duration>,
    ) -> PendingConnection<T> {
        PendingConnection::Rendezvous(Rendezvous::new(
            sock,
            local_public,
            remote_public,
            tsbpd_latency,
        ))
    }
}

impl<T> Future for PendingConnection<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        match *self {
            PendingConnection::Listen(ref mut l) => l.poll(),
            PendingConnection::Rendezvous(ref mut r) => r.poll(),
            PendingConnection::Connect(ref mut c) => c.poll(),
        }
    }
}
