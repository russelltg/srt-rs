use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;

use socket::SrtSocket;

pub struct PendingConnection {
    sock: SrtSocket,
    conn_type: ConnectionType,
}

enum ConnectionType {
    Listen,
    Connect(SocketAddr),
    Rendezvous {
        local_public: SocketAddr,
        remote_public: SocketAddr,
    },
}

impl PendingConnection {
    pub fn listen(sock: SrtSocket) -> PendingConnection {
        PendingConnection {
            sock,
            conn_type: ConnectionType::Listen,
        }
    }

    pub fn connect(sock: SrtSocket, remote_addr: SocketAddr) -> PendingConnection {
        PendingConnection {
            sock,
            conn_type: ConnectionType::Connect(remote_addr),
        }
    }

    pub fn rendezvous(
        sock: SrtSocket,
        local_public: SocketAddr,
        remote_public: SocketAddr,
    ) -> PendingConnection {
        PendingConnection {
            sock,
            conn_type: ConnectionType::Rendezvous {
                local_public,
                remote_public,
            },
        }
    }
}

impl Future for PendingConnection {
    // The future returns the socket back and the SocketAddr
    type Item = (SrtSocket, SocketAddr);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.conn_type {
            ConnectionType::Listen => {
                // wait for a packet
                let packet = try_ready!(self.sock.poll());

                // see if it's a handshake request
            }
            ConnectionType::Connect(_) => unimplemented!(),
            ConnectionType::Rendezvous { .. } => unimplemented!(),
        };
    }
}
