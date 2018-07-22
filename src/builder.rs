use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use failure::Error;
use rand;
use tokio_udp::{UdpFramed, UdpSocket};

use codec::PacketCodec;
use pending_connection::PendingConnection;
use SocketID;

pub type SrtSocket = UdpFramed<PacketCodec>;

/// Struct to build sockets
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    conn_type: ConnInitMethod,
    latency: Option<Duration>,
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
    pub fn new(conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            conn_type,
            latency: None,
        }
    }

    pub fn local_addr(&mut self, local_addr: IpAddr) {
        self.local_addr.set_ip(local_addr);
    }

    pub fn local_port(&mut self, port: u16) {
        self.local_addr.set_port(port)
    }

    pub fn latency(&mut self, latency: Duration) {
        println!("Configuring latency");
        self.latency = Some(latency);
    }

    pub fn build(self) -> Result<PendingConnection<SrtSocket>, Error> {
        trace!("Listening on {:?}", self.local_addr);

        let socket = UdpFramed::new(UdpSocket::bind(&self.local_addr)?, PacketCodec {});

        Ok(match self.conn_type {
            ConnInitMethod::Listen => {
                PendingConnection::listen(socket, SrtSocketBuilder::gen_sockid(), self.latency)
            }
            ConnInitMethod::Connect(addr) => PendingConnection::connect(
                socket,
                self.local_addr.ip(),
                addr,
                SrtSocketBuilder::gen_sockid(),
                self.latency,
            ),
            ConnInitMethod::Rendezvous {
                local_public,
                remote_public,
            } => PendingConnection::rendezvous(socket, local_public, remote_public, self.latency),
        })
    }

    pub fn gen_sockid() -> SocketID {
        SocketID(rand::random())
    }
}
