use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use failure::{bail, Error};
use rand;
use tokio::net::{UdpFramed, UdpSocket};

use crate::pending_connection;
use crate::MultiplexServer;
use crate::{ConnectionSettings, PacketCodec, Receiver, Sender, SrtCongestCtrl};

pub type SrtSocket = UdpFramed<PacketCodec>;

/// Struct to build sockets
#[derive(Debug, Clone)]
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    conn_type: ConnInitMethod,
    latency: Duration,
    crypto: Option<(u8, String)>,
}

#[derive(Debug, Clone, Copy)]
pub enum ConnInitMethod {
    Listen,
    Connect(SocketAddr),

    /// The public IP of the remote rendezvous client
    Rendezvous(SocketAddr),
}

impl SrtSocketBuilder {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    #[must_use]
    pub fn new(conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            conn_type,
            latency: Duration::from_millis(50),
            crypto: None,
        }
    }

    #[must_use]
    pub fn conn_type(&self) -> &ConnInitMethod {
        &self.conn_type
    }

    #[must_use]
    pub fn local_addr(mut self, local_addr: IpAddr) -> Self {
        self.local_addr.set_ip(local_addr);

        self
    }

    #[must_use]
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_addr.set_port(port);

        self
    }

    #[must_use]
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;

        self
    }

    #[must_use]
    pub fn crypto(mut self, size: u8, passphrase: String) -> Self {
        self.crypto = Some((size, passphrase));

        self
    }

    pub async fn connect_sender(self) -> Result<Sender<SrtSocket, SrtCongestCtrl>, Error> {
        let (sett, sock) = self.establish_conn().await?;
        Ok(Sender::new(sock, SrtCongestCtrl, sett))
    }

    pub async fn connect_receiver(self) -> Result<Receiver<SrtSocket>, Error> {
        let (sett, sock) = self.establish_conn().await?;
        Ok(Receiver::new(sock, sett))
    }

    async fn establish_conn(self) -> Result<(ConnectionSettings, SrtSocket), Error> {
        let mut socket = UdpFramed::new(UdpSocket::bind(&self.local_addr).await?, PacketCodec {});

        // validate crypto
        match self.crypto {
            // OK
            None | Some((16, _)) | Some((24, _)) | Some((32, _)) => {
                // TODO: Size validation
            }
            // not
            Some((size, _)) => {
                bail!("Invalid crypto size: {}. Expected 16, 24, or 32", size);
            }
        }

        Ok((
            match self.conn_type {
                ConnInitMethod::Listen => {
                    pending_connection::listen(&mut socket, rand::random(), self.latency).await?
                }
                ConnInitMethod::Connect(addr) => {
                    pending_connection::connect(
                        &mut socket,
                        addr,
                        rand::random(),
                        self.local_addr.ip(),
                        self.latency,
                        self.crypto.clone(),
                    )
                    .await?
                }
                ConnInitMethod::Rendezvous(remote_public) => {
                    pending_connection::rendezvous(
                        &mut socket,
                        rand::random(),
                        self.local_addr.ip(),
                        remote_public,
                        self.latency,
                    )
                    .await?
                }
            },
            socket,
        ))
    }

    pub async fn build_multiplexed(self) -> Result<MultiplexServer, Error> {
        match self.conn_type {
            ConnInitMethod::Listen => MultiplexServer::bind(&self.local_addr, self.latency).await,
            _ => bail!("Cannot bind multiplexed with any connection mode other than listen"),
        }
    }
}
