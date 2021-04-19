use std::{io, time::Duration};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use pending_connection::get_packet;
use tokio::net::UdpSocket;

use futures::{stream::unfold, Stream, StreamExt};

use crate::tokio::create_bidrectional_srt;
use crate::{crypto::CryptoOptions, multiplex, pending_connection, SrtSocket};
use log::error;
use srt_protocol::{
    accesscontrol::{AllowAllStreamAcceptor, StreamAcceptor},
    pending_connection::ConnInitSettings,
};

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// You need to decided on a [`ConnInitMethod`] in order to create a [`SrtSocketBuilder`]. See [that documentation](ConnInitMethod) for more details.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::SrtSocketBuilder;
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
/// # use srt_tokio::{SrtSocketBuilder, ConnInitMethod};
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
    local_addr: Option<IpAddr>,
    local_port: u16,
    conn_type: ConnInitMethod,
    init_settings: ConnInitSettings,
}

fn unspecified(is_ipv4: bool) -> IpAddr {
    if is_ipv4 {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    }
}

/// Describes how this SRT entity will connect to the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnInitMethod {
    /// Listens on the local socket, expecting there to be a [`Connect`](ConnInitMethod::Connect) instance that eventually connects to this socket.
    /// This almost certianly menas you should use it with [`SrtSocketBuilder::local_port`],
    /// As otherwise there is no way to know which port it will bind to.
    Listen,

    /// Connect to a listening socket. It expects the listen socket to be on the [`SocketAddr`] provided.
    /// If the second argument is provided, it is the streamid
    Connect(SocketAddr, Option<String>),

    /// Connect to another [`Rendezvous`](ConnInitMethod::Rendezvous) connection. This is useful if both sides are behind a NAT. The [`SocketAddr`]
    /// passed should be the **public** address and port of the other [`Rendezvous`](ConnInitMethod::Rendezvous) connection.
    Rendezvous(SocketAddr),
}

impl SrtSocketBuilder {
    /// Defaults to binding to all adaptors, OS assigned port, 50ms latency, and no encryption.
    /// In listen mode it defaults to IPv4 if not otherwise specified.
    /// Generally easier to use [`new_listen`](SrtSocketBuilder::new_listen), [`new_connect`](SrtSocketBuilder::new_connect) or [`new_rendezvous`](SrtSocketBuilder::new_rendezvous)
    pub fn new(conn_type: ConnInitMethod) -> Self {
        SrtSocketBuilder {
            local_addr: None,
            local_port: 0,
            conn_type,
            init_settings: ConnInitSettings::default(),
        }
    }

    /// Create a new listener, accepting one connection
    /// It would listen to IPv4 0.0.0.0 by default.
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
            None,
        ))
    }

    /// Connects to the first address yielded by `to`
    ///
    /// # Panics
    /// * `to` fails to resolve to a [`SocketAddr`]
    pub fn new_connect_with_streamid(to: impl ToSocketAddrs, streamid: impl Into<String>) -> Self {
        Self::new(ConnInitMethod::Connect(
            to.to_socket_addrs().unwrap().next().unwrap(),
            Some(streamid.into()),
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
    /// # use srt_tokio::{SrtSocketBuilder, ConnInitMethod};
    /// let builder = SrtSocketBuilder::new(ConnInitMethod::Listen);
    /// assert_eq!(builder.conn_type(), &ConnInitMethod::Listen);
    /// ```
    #[must_use]
    pub fn conn_type(&self) -> &ConnInitMethod {
        &self.conn_type
    }

    /// Sets the local address of the socket. This can be used to bind to just a specific network adapter instead of the default of all adapters.
    pub fn local_addr(mut self, local_addr: IpAddr) -> Self {
        self.local_addr = Some(local_addr);

        self
    }

    /// Sets the port to bind to. In general, to be used for [`ConnInitMethod::Listen`] and [`ConnInitMethod::Rendezvous`], but generally not [`ConnInitMethod::Connect`].
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = port;

        self
    }

    /// Set the latency of the connection. The more latency, the more time SRT has to recover lost packets.
    /// This sets both the send and receive latency
    pub fn latency(mut self, latency: Duration) -> Self {
        self.init_settings.send_latency = latency;
        self.init_settings.recv_latency = latency;

        self
    }

    // the minimum latency to receive at
    pub fn receive_latency(mut self, latency: Duration) -> Self {
        self.init_settings.recv_latency = latency;
        self
    }

    // the minimum latency to send at
    pub fn send_latency(mut self, latency: Duration) -> Self {
        self.init_settings.send_latency = latency;
        self
    }

    /// Se the crypto paramters. However, this is currently unimplemented.
    ///
    /// # Panics:
    /// * size is not 16, 24, or 32.
    pub fn crypto(mut self, size: u8, passphrase: impl Into<String>) -> Self {
        match size {
            // OK
            16 | 24 | 32 => {}
            // NOT
            size => panic!("Invaid crypto size {}", size),
        }
        self.init_settings.crypto = Some(CryptoOptions {
            size,
            passphrase: passphrase.into(),
        });

        self
    }

    /// Connect with a custom socket. Not typically used, see [`connect`](SrtSocketBuilder::connect) instead.
    pub async fn connect(self) -> Result<SrtSocket, io::Error> {
        let is_ipv4 = match self.conn_type {
            ConnInitMethod::Connect(addr, _) => addr.is_ipv4(),
            ConnInitMethod::Rendezvous(addr) => addr.is_ipv4(),
            ConnInitMethod::Listen => true,
        };

        let la = SocketAddr::new(
            self.local_addr.unwrap_or_else(|| unspecified(is_ipv4)),
            self.local_port,
        );
        let socket = UdpSocket::bind(&la).await?;

        let conn = match self.conn_type {
            ConnInitMethod::Listen => {
                pending_connection::listen(&socket, self.init_settings).await?
            }
            ConnInitMethod::Connect(addr, sid) => {
                let local_addr = self
                    .local_addr
                    .unwrap_or_else(|| unspecified(addr.is_ipv4()));
                if matches!(
                    (addr.ip(), local_addr),
                    (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_))
                ) {
                    error!("Mismatched address and local address ip family");
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                let r =
                    pending_connection::connect(&socket, addr, local_addr, self.init_settings, sid)
                        .await;

                r?
            }
            ConnInitMethod::Rendezvous(remote_public) => {
                let addr = self
                    .local_addr
                    .unwrap_or_else(|| unspecified(remote_public.is_ipv4()));
                let local_addr = SocketAddr::new(addr, self.local_port);
                pending_connection::rendezvous(
                    &socket,
                    local_addr,
                    remote_public,
                    self.init_settings,
                )
                .await?
            }
        };

        let socket = Arc::new(socket);
        let stream = unfold(socket.clone(), |sock| async {
            let pa = get_packet(&sock).await.unwrap();
            Some((pa, sock))
        })
        .boxed();

        Ok(create_bidrectional_srt(socket, stream, conn))
    }

    /// Connects to the remote socket. Resolves when it has been connected successfully.
    // pub async fn connect(self) -> Result<SrtSocket, io::Error> {
    //     Ok(self
    //         .connect_with_sock(UdpFramed::new(PacketCodec::new(la.is_ipv6())))
    //         .await?)
    // }

    /// Build a multiplexed connection. This acts as a sort of server, allowing many connections to this one socket.
    ///
    /// # Panics:
    /// If this is built with a non-listen builder
    pub async fn build_multiplexed(
        self,
    ) -> Result<impl Stream<Item = Result<SrtSocket, io::Error>>, io::Error> {
        self.build_multiplexed_with_acceptor(AllowAllStreamAcceptor::default())
            .await
    }

    pub async fn build_multiplexed_with_acceptor(
        self,
        acceptor: impl StreamAcceptor,
    ) -> Result<impl Stream<Item = Result<SrtSocket, io::Error>>, io::Error> {
        match self.conn_type {
            ConnInitMethod::Listen => {
                let addr = self
                    .local_addr
                    .unwrap_or_else(|| Ipv4Addr::UNSPECIFIED.into());
                let local_addr = SocketAddr::new(addr, self.local_port);
                multiplex(local_addr, self.init_settings, acceptor).await
            }
            _ => panic!("Cannot bind multiplexed with any connection mode other than listen"),
        }
    }
}
