use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use failure::{bail, Error};
use log::trace;
use rand;
use tokio_udp::{UdpFramed, UdpSocket};

use crate::packet::PacketCodec;
use crate::pending_connection::PendingConnection;
use crate::MultiplexServer;

pub type SrtSocket = UdpFramed<PacketCodec>;

/// Struct to build sockets
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    conn_type: ConnInitMethod,
    latency: Duration,
}

pub enum ConnInitMethod {
    Listen,
    Connect(SocketAddr),

    /// The public IP of the remote rendezvous client
    Rendezvous(SocketAddr),
}

impl SrtSocketBuilder {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    pub fn new(conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            conn_type,
            latency: Duration::from_millis(50),
        }
    }

    pub fn conn_type(&self) -> &ConnInitMethod {
        &self.conn_type
    }

    pub fn local_addr(&mut self, local_addr: IpAddr) -> &mut Self {
        self.local_addr.set_ip(local_addr);

        self
    }

    pub fn local_port(&mut self, port: u16) -> &mut Self {
        self.local_addr.set_port(port);

        self
    }

    pub fn latency(&mut self, latency: Duration) -> &mut Self {
        self.latency = latency;

        self
    }

    pub fn build(&mut self) -> Result<PendingConnection<SrtSocket>, Error> {
        trace!("Listening on {:?}", self.local_addr);

        let socket = UdpFramed::new(UdpSocket::bind(&self.local_addr)?, PacketCodec {});

        Ok(match self.conn_type {
            ConnInitMethod::Listen => {
                PendingConnection::listen(socket, rand::random(), self.latency)
            }
            ConnInitMethod::Connect(addr) => PendingConnection::connect(
                socket,
                self.local_addr.ip(),
                addr,
                rand::random(),
                self.latency,
            ),
            ConnInitMethod::Rendezvous(remote_public) => PendingConnection::rendezvous(
                socket,
                rand::random(),
                self.local_addr.ip(),
                remote_public,
                self.latency,
            ),
        })
    }

    pub fn build_multiplexed(&mut self) -> Result<MultiplexServer, Error> {
        match self.conn_type {
            ConnInitMethod::Listen => MultiplexServer::bind(&self.local_addr, self.latency),
            _ => bail!("Cannot bind multiplexed with any connection mode other than listen"),
        }
    }
}
