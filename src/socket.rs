use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{Cursor, Error, ErrorKind, Result};


use tokio::net::UdpSocket;

use futures::prelude::*;

use packet::Packet;

use bytes::BytesMut;

/// Struct to build sockets
pub struct SrtSocketBuilder<T: ToSocketAddrs, U: ToSocketAddrs> {
    local_addr: T,
    connect_addr: Option<U>,
}

impl<T: ToSocketAddrs, U: ToSocketAddrs> SrtSocketBuilder<T, U> {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    pub fn new(local_addr: T) -> Self {
        SrtSocketBuilder {
            local_addr,
            connect_addr: None,
        }
    }

    /// Set the address to connect to
    pub fn connet_to(mut self, connet_addr: U) -> Self {
        self.connect_addr = Some(connet_addr);

        self
    }

    pub fn build(self) -> Result<SrtSocket> {
        Ok(SrtSocket {
            socket: UdpSocket::bind(
                match self.local_addr.to_socket_addrs()?.next() {
                    Some(ref a) => a,
                    None => {
                        return Err(Error::new(
                            ErrorKind::AddrNotAvailable,
                            "Could not get an addr from the given addr",
                        ));
                    }
                },
            )?,
            buffer: BytesMut::new(),
        })
    }
}

pub struct SrtSocket {
    socket: UdpSocket,
    buffer: BytesMut,

}

