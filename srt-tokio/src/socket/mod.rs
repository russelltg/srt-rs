mod builder;
mod call;
mod listen;
mod rendezvous;

pub(crate) mod factory;

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant, fmt::Debug,
};

use bytes::Bytes;
use futures::{
    channel::mpsc::{self, TrySendError},
    prelude::*,
    ready,
    stream::Peekable,
};
use srt_protocol::{
    connection::ConnectionSettings,
    options::{OptionsError, OptionsOf, SocketOptions, Validation},
};
use tokio::{net::UdpSocket, task::JoinHandle};

use super::{net::*, options::BindOptions, watch};

pub use builder::SrtSocketBuilder;
pub use srt_protocol::statistics::SocketStatistics;

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementation to send or receive data.
///
/// The sockets yield and consume `(Instant, Bytes)`, representing the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
#[derive(Debug)]
pub struct SrtSocket {
    output_data_receiver: Peekable<mpsc::Receiver<(Instant, Bytes)>>,
    input_data_sender: mpsc::Sender<(Instant, Bytes)>,
    statistics_receiver: watch::Receiver<SocketStatistics>,
    settings: ConnectionSettings,
    task: JoinHandle<()>,
}

impl SrtSocket {
    pub fn builder() -> SrtSocketBuilder {
        SrtSocketBuilder::default()
    }

    pub fn try_send(&mut self, srctime: Instant, data: Bytes) -> Result<(), (Instant, Bytes)> {
        self.input_data_sender
            .try_send((srctime, data))
            .map_err(TrySendError::into_inner)
    }

    pub fn with<O>(options: O) -> SrtSocketBuilder
    where
        SocketOptions: OptionsOf<O>,
        O: Validation<Error = OptionsError>,
    {
        Self::builder().with(options)
    }

    pub async fn bind(options: BindOptions) -> Result<Self, io::Error> {
        use BindOptions::*;
        let socket_options = match &options {
            Listen(options) => &options.socket,
            Call(options) => &options.socket,
            Rendezvous(options) => &options.socket,
        };
        let socket = bind_socket(socket_options).await?;
        Self::bind_with_socket(options, socket).await
    }

    async fn bind_with_socket(options: BindOptions, socket: UdpSocket) -> Result<Self, io::Error> {
        let socket = PacketSocket::from_socket(Arc::new(socket), 1024 * 1024);

        use BindOptions::*;
        let (socket, connection) = match options {
            Listen(options) => listen::bind_with(socket, options).await?,
            Call(options) => call::bind_with(socket, options).await?,
            Rendezvous(options) => rendezvous::bind_with(socket, options).await?,
        };

        let (new_socket, new_state) = factory::split_new();
        let (task, settings) = new_state.spawn_task(socket, connection);
        let socket = new_socket.create_socket(settings, task);

        Ok(socket)
    }

    pub async fn close_and_finish(&mut self) -> Result<(), io::Error> {
        self.close().await?;
        (&mut self.task).await?;
        Ok(())
    }

    pub fn split_mut(
        &mut self,
    ) -> (
        Pin<&mut Peekable<impl Stream<Item = (Instant, Bytes)> + Unpin>>,
        Pin<&mut (impl Sink<(Instant, Bytes), Error=impl Debug> + Unpin)>,
    ) {
        (
            Pin::new(&mut self.output_data_receiver),
            Pin::new(&mut self.input_data_sender),
        )
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn statistics(&mut self) -> &mut (impl Stream<Item = SocketStatistics> + Clone) {
        &mut self.statistics_receiver
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(Pin::new(&mut self.output_data_receiver).poll_next(cx)).map(Ok))
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(ready!(
            Pin::new(&mut self.input_data_sender).poll_ready(cx)
        )
        .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?))
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        self.input_data_sender
            .start_send(item)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.input_data_sender)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.input_data_sender)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
}
