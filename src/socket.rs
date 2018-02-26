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
            socket: SocketOr::U(UdpSocket::bind(
                match self.local_addr.to_socket_addrs()?.next() {
                    Some(ref a) => a,
                    None => {
                        return Err(Error::new(
                            ErrorKind::AddrNotAvailable,
                            "Could not get an addr from the given addr",
                        ));
                    }
                },
            )?),
            buffer: BytesMut::new(),
        })
    }
}

enum SocketOr {
    U(UdpSocket),
    F(Box<Future<Item = (UdpSocket, Vec<u8>, usize, SocketAddr), Error = Error>>),
}

pub struct SrtSocket {
    socket: SocketOr,
    buffer: BytesMut,
}

impl Stream for SrtSocket {
    type Item = Packet;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // make sure the buffer is big enough. Should be a one-time op
        self.buffer.reserve(65536);

        // Read from the socket

        // parse the packet

        // freeze the buffer, wont' change now
        let buf_frozen = self.buffer.freeze();

        let packet = Packet::parse(Cursor::new(buf_frozen))?;

        // go back to mut
        self.buffer = buf_frozen.try_mut().unwrap();

        return Ok(Async::Ready(Some(packet)));
    }
}
