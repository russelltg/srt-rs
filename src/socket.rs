use std::net::SocketAddr;
use std::io::{Error, Result};
use std::time::Instant;

use tokio::net::{UdpFramed, UdpSocket};
use rand::{thread_rng, Rng};

use packet::Packet;
use pending_connection::PendingConnection;
use codec::PacketCodec;

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

    pub fn build(self) -> Result<PendingConnection<SrtSocket>> {
        trace!("Listening on {:?}", self.local_addr);

        let socket = SrtSocket {
            sock: UdpFramed::new(UdpSocket::bind(&self.local_addr)?, PacketCodec {}),
        };

        Ok(match self.connect_addr {
            Some(addr) => PendingConnection::connect(socket, addr),
            None => PendingConnection::listen(socket, SrtSocketBuilder::gen_sockid(), Instant::now()),
        })
    }

    pub fn build_raw(self) -> Result<SrtSocket> {
        Ok(SrtSocket {
            sock: UdpFramed::new(UdpSocket::bind(&self.local_addr)?, PacketCodec {}),
        })
    }

    pub fn gen_sockid() -> i32 {
        thread_rng().gen::<i32>()
    }
}

pub struct SrtSocket {
    pub sock: UdpFramed<PacketCodec>,
}

impl Stream for SrtSocket {
    type Item = (Packet, SocketAddr);
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.sock.poll()
    }
}

impl Sink for SrtSocket {
    type SinkItem = (Packet, SocketAddr);
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.sock.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        self.sock.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Error> {
        self.sock.close()
    }
}
