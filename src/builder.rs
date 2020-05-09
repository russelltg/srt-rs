use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::{io, time::Duration};

use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use futures::{future::ready, Sink, Stream, StreamExt};

use crate::tokio::create_bidrectional_srt;
use crate::{
    multiplex, pending_connection, Connection, PackChan, Packet, PacketCodec, PacketParseError,
    SrtSocket,
};
use log::warn;

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// You need to decided on a [`ConnInitMethod`] in order to create a [`SrtSocketBuilder`]. See [that documentation](ConnInitMethod) for more details.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt::SrtSocketBuilder;
/// # use std::io;
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocketBuilder::new_listen().local_port(3333).connect(),
///     SrtSocketBuilder::new_connect("127.0.0.1:3333").connect(),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// Rendezvous example:
///
/// ```
/// # use srt::{SrtSocketBuilder, ConnInitMethod};
/// # use std::io;
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocketBuilder::new_rendezvous("127.0.0.1:4444").local_port(5555).connect(),
///     SrtSocketBuilder::new_rendezvous("127.0.0.1:5555").local_port(4444).connect(),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// # Panics:
/// * There is no tokio runtime
#[derive(Debug, Clone)]
#[must_use]
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    conn_type: ConnInitMethod,
    latency: Duration,
    crypto: Option<(u8, String)>,
}

/// Describes how this SRT entity will connect to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnInitMethod {
    /// Listens on the local socket, expecting there to be a [`Connect`](ConnInitMethod::Connect) instance that eventually connects to this socket.
    /// This almost certianly menas you should use it with [`SrtSocketBuilder::local_port`],
    /// As otherwise there is no way to know which port it will bind to.
    Listen,

    /// Connect to a listening socket. It expects the listen socket to be on the [`SocketAddr`] provided.
    Connect(SocketAddr),

    /// Connect to another [`Rendezvous`](ConnInitMethod::Rendezvous) connection. This is useful if both sides are behind a NAT. The [`SocketAddr`]
    /// passed should be the **public** address and port of the other [`Rendezvous`](ConnInitMethod::Rendezvous) connection.
    Rendezvous(SocketAddr),
}

impl SrtSocketBuilder {
    /// Defaults to binding to `0.0.0.0:0` (all adaptors, OS assigned port), 50ms latency, and no encryption.
    /// Generally easier to use [`new_listen`](SrtSocketBuilder::new_listen), [`new_connect`](SrtSocketBuilder::new_connect) or [`new_rendezvous`](SrtSocketBuilder::new_rendezvous)
    pub fn new(conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            conn_type,
            latency: Duration::from_millis(50),
            crypto: None,
        }
    }

    pub fn new_listen() -> Self {
        Self::new(ConnInitMethod::Listen)
    }

    /// Connects to the first address yielded by `to`
    ///
    /// # Panics
    /// * `to` fails to resolve to a [`SocketAddr`]
    pub fn new_connect(to: impl ToSocketAddrs) -> Self {
        Self::new(ConnInitMethod::Connect(
            to.to_socket_addrs().unwrap().next().unwrap(),
        ))
    }

    /// Connects to the first address yielded by `to`
    ///
    /// # Panics
    /// * `to` fails to resolve to a [`SocketAddr`]
    pub fn new_rendezvous(to: impl ToSocketAddrs) -> Self {
        Self::new(ConnInitMethod::Rendezvous(
            to.to_socket_addrs().unwrap().next().unwrap(),
        ))
    }

    /// Gets the [`ConnInitMethod`] of the builder.
    ///
    /// ```
    /// # use srt::{SrtSocketBuilder, ConnInitMethod};
    /// let builder = SrtSocketBuilder::new(ConnInitMethod::Listen);
    /// assert_eq!(builder.conn_type(), &ConnInitMethod::Listen);
    /// ```
    #[must_use]
    pub fn conn_type(&self) -> &ConnInitMethod {
        &self.conn_type
    }

    /// Sets the local address of the socket. This can be used to bind to just a specific network adapter instead of the default of all adapters.
    pub fn local_addr(mut self, local_addr: IpAddr) -> Self {
        self.local_addr.set_ip(local_addr);

        self
    }

    /// Sets the port to bind to. In general, to be used for [`ConnInitMethod::Listen`] and [`ConnInitMethod::Rendezvous`], but generally not [`ConnInitMethod::Connect`].
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_addr.set_port(port);

        self
    }

    /// Set the latency of the connection. The more latency, the more time SRT has to recover lost packets.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;

        self
    }

    /// Se the crypto paramters. However, this is currently unimplemented.
    ///
    /// # Panics:
    /// * size is not 16, 24, or 32.
    pub fn crypto(mut self, size: u8, passphrase: String) -> Self {
        match size {
            // OK
            16 | 24 | 32 => {}
            // NOT
            // TODO: size validation
            size => panic!("Invaid crypto size {}", size),
        }
        self.crypto = Some((size, passphrase));

        self
    }

    /// Connect with a custom socket. Not typically used, see [`connect`](SrtSocketBuilder::connect) instead.
    pub async fn connect_with_sock<T>(self, mut socket: T) -> Result<SrtSocket, io::Error>
    where
        T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
            + Sink<(Packet, SocketAddr), Error = io::Error>
            + Unpin
            + Send
            + 'static,
    {
        let conn = match self.conn_type {
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
                    self.local_addr,
                    remote_public,
                    self.latency,
                )
                .await?
            }
        };

        Ok(create_bidrectional_srt(
            socket.filter_map(|res| {
                ready(res.map_err(|e| warn!("Error parsing packet: {}", e)).ok())
            }),
            conn,
        ))
    }

    /// Connects to the remote socket. Resolves when it has been connected successfully.
    pub async fn connect(self) -> Result<SrtSocket, io::Error> {
        let la = self.local_addr;
        Ok(self
            .connect_with_sock(UdpFramed::new(UdpSocket::bind(&la).await?, PacketCodec {}))
            .await?)
    }

    /// Build a multiplexed connection. This acts as a sort of server, allowing many connections to this one socket.
    ///
    /// # Panics:
    /// If this is built with a non-listen builder
    pub async fn build_multiplexed(
        self,
    ) -> Result<impl Stream<Item = Result<(Connection, PackChan), io::Error>>, io::Error> {
        match self.conn_type {
            ConnInitMethod::Listen => multiplex(self.local_addr, self.latency).await,
            _ => panic!("Cannot bind multiplexed with any connection mode other than listen"),
        }
    }
}
