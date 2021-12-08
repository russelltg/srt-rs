use std::{convert::TryInto, io, time::Duration};

use tokio::net::UdpSocket;

use crate::options::*;

use super::SrtListener;

#[derive(Default)]
pub struct SrtListenerBuilder(SocketOptions, Option<UdpSocket>);

/// Struct to build a multiplexed listener.
///
/// This is the typical way to create instances of [`SrtListener`].
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::{SrtListener, options::*};
/// # use std::{io, time::Duration};
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let listener = SrtListener::builder()
///         .set(|options| {
///             options.connect.timeout = Duration::from_secs(2);
///             options.receiver.buffer_size = ByteCount(120000);
///             options.sender.max_payload_size = PacketSize(1200);
///             options.session.peer_idle_timeout = Duration::from_secs(5);
///         }).bind("127.0.0.1:4444").await?;
/// # Ok(())
/// # }
/// ```
///
/// # Panics:
/// * There is no tokio runtime
impl SrtListenerBuilder {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind() {
        // just a test to exercise all the builder methods to ensure they don't explode
        let socket = UdpSocket::bind("0.0.0.0:9999").await.unwrap();
        let _ = SrtListener::builder()
            .with(Encryption {
                key_size: KeySize::AES256,
                km_refresh: KeyMaterialRefresh {
                    period: PacketCount(1000),
                    pre_announcement_period: PacketCount(400),
                },
                ..Default::default()
            })
            .set(|options| options.receiver.buffer_size = ByteCount(1_000_000))
            .receive_latency(Duration::from_secs(2))
            .send_latency(Duration::from_secs(4))
            .latency(Duration::from_secs(1))
            .encryption(0, "super secret passcode")
            .bandwidth(LiveBandwidthMode::Set(DataRate(1_000_000)))
            .socket(socket)
            .bind(":9999")
            .await
            .unwrap();
    }
}
