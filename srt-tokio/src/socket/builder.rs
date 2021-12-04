use std::convert::TryInto;
use std::{
    io,
    net::{IpAddr, ToSocketAddrs},
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::options::*;

use super::SrtSocket;

#[derive(Default)]
pub struct NewSrtSocket(SocketOptions, Option<UdpSocket>);

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// You need to decided on a [`ConnInitMethod`] in order to create a [`SrtSocketBuilder`]. See [that documentation](ConnInitMethod) for more details.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::SrtSocket;
/// # use std::io;
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocket::new().local_ip("127.0.0.1".parse().unwrap()).local_port(3333).listen(),
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
///             options.connect.local_port = 4444;
///             options.receiver.buffer_size = 1200000;
///             options.sender.max_payload_size = 1200;
///             options.session.peer_idle_timeout = Duration::from_secs(5);
///         })
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
        self.0.connect.local_ip = ip;

        self
    }

    /// Sets the port to bind to. In general, to be used for [`Listen`] and [`Rendezvous`], but generally not [`Call`].
    pub fn local_port(mut self, port: u16) -> Self {
        self.0.connect.local_port = port;
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

    pub fn with2<O1, O2>(mut self, options1: O1, options2: O2) -> Self
    where
        SocketOptions: OptionsOf<O1> + OptionsOf<O2>,
        O1: Validation<Error = OptionsError>,
        O2: Validation<Error = OptionsError>,
    {
        self.0.set_options(options1);
        self.0.set_options(options2);
        self
    }

    pub fn set(mut self, set_fn: impl FnOnce(&mut SocketOptions)) -> Self {
        set_fn(&mut self.0);
        self
    }

    pub async fn listen(self) -> Result<SrtSocket, io::Error> {
        let options = ListenerOptions::new(self.0.connect.local_port)?.with(self.0)?;
        Self::bind(options.into(), self.1).await
    }

    pub async fn call(
        self,
        remote_address: impl ToSocketAddrs,
        stream_id: Option<&str>,
    ) -> Result<SrtSocket, io::Error> {
        let options = CallerOptions::new(remote_address, stream_id)?.with(self.0)?;
        Self::bind(options.into(), self.1).await
    }

    pub async fn rendezvous(
        self,
        remote_address: impl ToSocketAddrs,
    ) -> Result<SrtSocket, io::Error> {
        let options = RendezvousOptions::new(remote_address)?.with(self.0)?;
        Self::bind(options.into(), self.1).await
    }

    async fn bind(options: BindOptions, socket: Option<UdpSocket>) -> Result<SrtSocket, io::Error> {
        match socket {
            None => SrtSocket::bind(options).await,
            Some(socket) => SrtSocket::bind_with_socket(options, socket).await,
        }
    }
}
