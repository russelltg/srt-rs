use std::io::{Error, Result};
use std::net::SocketAddr;
use std::time::Instant;

use rand::{thread_rng, Rng};
use tokio::net::{UdpFramed, UdpSocket};

use codec::PacketCodec;
use packet::Packet;
use pending_connection::PendingConnection;

use futures::prelude::*;

pub type SrtSocket = UdpFramed<PacketCodec>;

/// Struct to build sockets
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    conn_type: ConnInitMethod,
}

pub enum ConnInitMethod {
    Listen,
    Connect(SocketAddr),
    Rendezvous {
        local_public: SocketAddr,
        remote_public: SocketAddr,
    },
}

impl SrtSocketBuilder {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    pub fn new(local_addr: SocketAddr, conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr,
            conn_type,
        }
    }

    pub fn build(self) -> Result<PendingConnection<SrtSocket>> {
        trace!("Listening on {:?}", self.local_addr);

        let socket = UdpFramed::new(UdpSocket::bind(&self.local_addr)?, PacketCodec {});

        Ok(match self.conn_type {
            ConnInitMethod::Listen => {
                PendingConnection::listen(socket, SrtSocketBuilder::gen_sockid(), Instant::now())
            }
            ConnInitMethod::Connect(addr) => PendingConnection::connect(socket, addr),
            ConnInitMethod::Rendezvous {
                local_public,
                remote_public,
            } => PendingConnection::rendezvous(socket, local_public, remote_public),
        })
    }

    pub fn gen_sockid() -> i32 {
        thread_rng().gen::<i32>()
    }
}
