use std::{convert::TryInto, io, time::Duration};

use tokio::net::UdpSocket;

use crate::options::*;

use super::SrtListener;

#[derive(Default)]
pub struct NewSrtListener(SocketOptions, Option<UdpSocket>);

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// You need to decided on a [`ConnInitMethod`] in order to create a [`SrtSocketBuilder`]. See [that documentation](ConnInitMethod) for more details.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::SrtListener;
/// # use std::{io, time::Duration};
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
///     let listener = SrtListener::new()
///         .set(|options| {
///             options.connect.timeout = Duration::from_secs(2);
///             options.receiver.buffer_size = 1200000;
///             options.sender.max_payload_size = 1200;
///             options.session.peer_idle_timeout = Duration::from_secs(5);
///         }).bind("127.0.0.1:4444").await?;
/// # Ok(())
/// # }
/// ```
///
/// # Panics:
/// * There is no tokio runtime
impl NewSrtListener {
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

    pub async fn bind(self, local: impl TryInto<SocketAddress>) -> Result<SrtListener, io::Error> {
        let options = ListenerOptions::with(local, self.0)?;
        match self.1 {
            None => SrtListener::bind(options).await,
            Some(socket) => SrtListener::bind_with_socket(options, socket).await,
        }
    }
}
