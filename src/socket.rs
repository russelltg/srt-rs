use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{Error, ErrorKind, Result};
use std::collections::VecDeque;

use tokio::net::UdpSocket;

use packet::Packet;

use bytes::BytesMut;

use futures::prelude::*;

/// Struct to build sockets
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    connect_addr: Option<SocketAddr>,
}

impl SrtSocketBuilder {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    pub fn new(local_addr: SocketAddr) -> Self {
        SrtSocketBuilder {
            local_addr,
            connect_addr: None,
        }
    }

    /// Set the address to connect to
    pub fn connet_to(mut self, connet_addr: SocketAddr) -> Self {
        self.connect_addr = Some(connet_addr);

        self
    }

    pub fn build(self) -> Result<SrtSocket> {

        // start listening
        let sock = UdpSocket::bind(self.local_addr.clone())?;

        Ok(SrtSocket {
            addr: self.local_addr,
            queue: VecDeque::new(),
            future: SocketFuture::Recv(sock.recv_dgram(BytesMut::with_capacity(54436))),
        })
    }
}

pub enum SocketFuture {
    Send(Box<Future<Item = (UdpSocket, T, usize, SocketAddr), Error=Error>>),
    Recv(Box<Future<Item = (UdpSocket, BytesMut), Error=Error>>),
}

pub struct SrtSocket {
    addr: SocketAddr,
    queue: VecDeque<Packet>,

    future: SocketFuture,
}

impl Stream for SrtSocket {
    type Item = Packet;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Packet>, Error> {
        
    }
}
