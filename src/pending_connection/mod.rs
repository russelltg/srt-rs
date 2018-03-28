pub mod listen;
pub mod connect;
pub mod rendezvous;

use std::io::{Error};
use std::net::SocketAddr;

use futures::prelude::*;

use connected::Connected;
use socket::SrtSocket;
use receiver::Receiver;

pub use self::listen::Listen;
pub use self::connect::Connect;
pub use self::rendezvous::Rendezvous;

pub enum PendingConnection {
	Listen(Listen),
	Rendezvous(Rendezvous),
	Connect(Connect),
}

impl PendingConnection {
    pub fn listen(sock: SrtSocket) -> PendingConnection {
        PendingConnection::Listen(Listen::new(
            sock
        ))
    }

    pub fn connect(sock: SrtSocket, remote_addr: SocketAddr) -> PendingConnection {
		PendingConnection::Connect(Connect::new(
			sock,
			remote_addr,
		))
    }

    pub fn rendezvous(
        sock: SrtSocket,
        local_public: SocketAddr,
        remote_public: SocketAddr,
    ) -> PendingConnection {
		PendingConnection::Rendezvous(Rendezvous::new(sock, local_public, remote_public))
    }
}

impl Future for PendingConnection {
    type Item = Connected;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected, Error> {
		match *self {
			PendingConnection::Listen(ref mut l) => l.poll(),
			PendingConnection::Rendezvous(ref mut r) => r.poll(),
			PendingConnection::Connect(ref mut c) => c.poll(),
		}
    }
}
