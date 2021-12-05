use std::net::SocketAddr;
use std::{convert::TryInto, io, net::IpAddr, time::Duration};

use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};

use crate::options::*;

use super::SrtSocket;

#[derive(Default)]
pub struct NewSrtSocket(SocketOptions, Option<UdpSocket>);

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::SrtSocket;
/// # use std::io;
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocket::new().listen(":3333"),
///     SrtSocket::new().call("127.0.0.1:3333", Some("stream ID")),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// Rendezvous example:
///
/// ```
/// # use srt_tokio::SrtSocket;
/// # use std::{io, time::Duration};
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocket::new().local_port(5555).rendezvous("127.0.0.1:4444"),
///     SrtSocket::new()
///         .set(|options| {
///             options.connect.timeout = Duration::from_secs(2);
///             options.receiver.buffer_size = 1200000;
///             options.sender.max_payload_size = 1200;
///             options.session.peer_idle_timeout = Duration::from_secs(5);
///         })
///         .local_port(4444)
///         .rendezvous("127.0.0.1:5555"),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// # Panics:
/// * There is no tokio runtime
impl NewSrtSocket {
    /// Sets the local address of the socket. This can be used to bind to just a specific network adapter instead of the default of all adapters.
    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        let local = self.0.connect.local;
        self.0.connect.local = SocketAddr::new(ip, local.port());
        self
    }

    /// Sets the port to bind to. In general, to be used for [`Listen`] and [`Rendezvous`], but generally not [`Call`].
    pub fn local_port(mut self, port: u16) -> Self {
        let local = self.0.connect.local;
        self.0.connect.local = SocketAddr::new(local.ip(), port);
        self
    }

    /// Sets the local address (ip:port) to bind to. In general, to be used for [`Listen`] and [`Rendezvous`], but generally not [`Call`].
    pub fn local(mut self, address: impl TryInto<SocketAddress>) -> Self {
        let address = address
            .try_into()
            .map_err(|_| OptionsError::InvalidLocalAddress)
            .unwrap();
        self.0.connect.local = address.into();
        self
    }

    /// Set the latency of the connection. The more latency, the more time SRT has to recover lost packets.
    /// This sets both the send and receive latency
    pub fn latency(mut self, latency: Duration) -> Self {
        self.0.sender.peer_latency = latency;
        self.0.receiver.latency = latency;

        self
    }

    /// Set the encryption parameters.
    ///
    /// # Panics:
    /// * size is not 0, 16, 24, or 32.
    pub fn encryption(mut self, key_size: u8, passphrase: impl Into<String>) -> Self {
        self.0.encryption.key_size = key_size.try_into().unwrap();
        self.0.encryption.passphrase = Some(passphrase.into().try_into().unwrap());

        self
    }
    /// the minimum latency to receive at
    pub fn receive_latency(mut self, latency: Duration) -> Self {
        self.0.receiver.latency = latency;
        self
    }

    /// the minimum latency to send at
    pub fn send_latency(mut self, latency: Duration) -> Self {
        self.0.sender.peer_latency = latency;
        self
    }

    pub fn bandwidth(mut self, bandwidth: LiveBandwidthMode) -> Self {
        self.0.sender.bandwidth = bandwidth;
        self
    }

    pub fn socket(mut self, socket: UdpSocket) -> Self {
        self.1 = Some(socket);
        self
    }

    pub fn with<O>(mut self, options: O) -> Self
    where
        SocketOptions: OptionsOf<O>,
        O: Validation<Error = OptionsError>,
    {
        self.0.set_options(options);
        self
    }

    pub fn set(mut self, set_fn: impl FnOnce(&mut SocketOptions)) -> Self {
        set_fn(&mut self.0);
        self
    }

    pub async fn listen(self, local: impl TryInto<SocketAddress>) -> Result<SrtSocket, io::Error> {
        let options = ListenerOptions::with(local, self.0)?;
        Self::bind(options.into(), self.1).await
    }

    pub async fn call(
        self,
        remote_address: impl ToSocketAddrs,
        stream_id: Option<&str>,
    ) -> Result<SrtSocket, io::Error> {
        let address = lookup_host(remote_address)
            .await?
            .next()
            .ok_or(OptionsError::InvalidRemoteAddress)?;
        let options = CallerOptions::with(address, stream_id, self.0)?;
        Self::bind(options.into(), self.1).await
    }

    pub async fn rendezvous(
        self,
        remote_address: impl ToSocketAddrs,
    ) -> Result<SrtSocket, io::Error> {
        let address = lookup_host(remote_address)
            .await?
            .next()
            .ok_or(OptionsError::InvalidRemoteAddress)?;
        let options = RendezvousOptions::with(address, self.0)?;
        Self::bind(options.into(), self.1).await
    }

    async fn bind(options: BindOptions, socket: Option<UdpSocket>) -> Result<SrtSocket, io::Error> {
        match socket {
            None => SrtSocket::bind(options).await,
            Some(socket) => SrtSocket::bind_with_socket(options, socket).await,
        }
    }
}
