pub mod connect;
pub mod listen;
pub mod rendezvous;

use std::io::Error;
use std::net::SocketAddr;
use std::time::Instant;

use futures::prelude::*;

use connected::Connected;

pub use self::connect::Connect;
pub use self::listen::Listen;
pub use self::rendezvous::Rendezvous;
pub use Packet;

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
        local_socket_id: i32,
        socket_start_time: Instant,
    ) -> PendingConnection<T> {
        PendingConnection::Listen(Listen::new(sock, local_socket_id, socket_start_time))
    }

    pub fn connect(sock: T, remote_addr: SocketAddr) -> PendingConnection<T> {
        PendingConnection::Connect(Connect::new(sock, remote_addr))
    }

    pub fn rendezvous(
        sock: T,
        local_public: SocketAddr,
        remote_public: SocketAddr,
    ) -> PendingConnection<T> {
        PendingConnection::Rendezvous(Rendezvous::new(sock, local_public, remote_public))
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
