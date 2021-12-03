mod builder;
mod state;

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures::{
    channel::mpsc::{self, Receiver, Sender},
    prelude::*,
    ready, select,
};
use log::{error, trace};
use srt_protocol::{
    connection::{Action, Connection, ConnectionSettings, DuplexConnection, Input},
    options::{OptionsError, OptionsOf, SocketOptions, Validation},
    packet::*,
};
use tokio::{task::JoinHandle, time::sleep_until};
use tokio::net::UdpSocket;

use super::{net::*, watch, options::BindOptions};

use builder::NewSrtSocket;

pub use srt_protocol::statistics::SocketStatistics;

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementatino to send or receive data.
///
/// The sockets yield and consume `(Instant, Bytes)`, representng the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
#[derive(Debug)]
pub struct SrtSocket {
    // receiver datastructures
    output_data: mpsc::Receiver<(Instant, Bytes)>,

    // sender datastructures
    input_data: mpsc::Sender<(Instant, Bytes)>,

    statistics: watch::Receiver<SocketStatistics>,

    settings: ConnectionSettings,
}

impl SrtSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> NewSrtSocket {
        NewSrtSocket::default()
    }

    pub async fn bind(options: impl Into<BindOptions>) -> Result<Self, io::Error> {
        let options = options.into();
        use BindOptions::*;
        let socket_options = match &options {
            Listen(options) => &options.socket,
            Call(options) => &options.socket,
            Rendezvous(options) => &options.socket,
        };
        let socket = UdpSocket::bind(socket_options.local_address()).await?;

        Self::bind_with_socket(options, socket).await
    }

    pub async fn bind_with_socket(options: impl Into<BindOptions>, socket: UdpSocket) -> Result<Self, io::Error> {
        let options = options.into();
        let mut socket = PacketSocket::from_socket(Arc::new(socket), 1024 * 1024);
        use BindOptions::*;
        let conn = match options {
            Listen(options) =>
                crate::pending_connection::listen(&mut socket, options.socket.clone().into()).await?,
            Call(options) =>
                crate::pending_connection::connect(
                    &mut socket,
                    options.remote,
                    options.socket.connect.local_ip,
                    options.socket.clone().into(),
                    Some(options.stream_id.to_string()),
                    rand::random(),
                )
                    .await?,
            Rendezvous(options) => crate::pending_connection::rendezvous(
                &mut socket,
                SocketAddr::new(options.socket.connect.local_ip, options.socket.connect.local_port),
                options.remote,
                options.socket.clone().into(),
                rand::random(),
            )
                .await?,
        };

        Ok(create_bidrectional_srt(socket, conn))

    }

    pub fn with<O>(options: O) -> NewSrtSocket
    where
        SocketOptions: OptionsOf<O>,
        O: Validation<Error = OptionsError>,
    {
        NewSrtSocket::default().with(options)
    }

    pub(crate) fn create(
        settings: ConnectionSettings,
        input_data_sender: mpsc::Sender<(Instant, Bytes)>,
        output_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
        statistics_receiver: watch::Receiver<SocketStatistics>,
    ) -> SrtSocket {
        SrtSocket {
            settings,
            output_data: output_data_receiver,
            input_data: input_data_sender,
            statistics: statistics_receiver,
        }
    }

    pub(crate) fn spawn(
        conn: Connection,
        socket: PacketSocket,
        input_data_receiver: mpsc::Receiver<(Instant, Bytes)>,
        output_data_sender: mpsc::Sender<(Instant, Bytes)>,
        statistics_sender: watch::Sender<SocketStatistics>,
    ) -> (JoinHandle<()>, ConnectionSettings) {
        let settings = conn.settings.clone();

        let handle = tokio::spawn(async move {
            // Using run_input_loop breaks a couple of the stransmit_interop tests.
            // Both stransmit_decrypt and stransmit_server run indefinitely. For now,
            // run_handler_loop exclusively, until a fix is found or an API decision
            // is reached.
            if Instant::now().elapsed().as_nanos() != 0 {
                run_handler_loop(
                    socket,
                    statistics_sender,
                    output_data_sender,
                    input_data_receiver,
                    conn,
                )
                .await;
            } else {
                run_input_loop(
                    socket,
                    statistics_sender,
                    output_data_sender,
                    input_data_receiver,
                    conn,
                )
                .await;
            }
        });

        (handle, settings)
    }
}

/// This spawns a new task for the socket I/O loop
pub fn create_bidrectional_srt(socket: PacketSocket, conn: Connection) -> SrtSocket {
    let (output_data_sender, output_data_receiver) = mpsc::channel(128);
    let (input_data_sender, input_data_receiver) = mpsc::channel(128);
    let (statistics_sender, statistics_receiver) = watch::channel();

    let (_, settings) = SrtSocket::spawn(
        conn,
        socket,
        input_data_receiver,
        output_data_sender,
        statistics_sender,
    );

    SrtSocket::create(
        settings,
        input_data_sender,
        output_data_receiver,
        statistics_receiver,
    )
}

async fn run_handler_loop(
    socket: PacketSocket,
    statistics_sender: watch::Sender<SocketStatistics>,
    output_data: mpsc::Sender<(Instant, Bytes)>,
    input_data: mpsc::Receiver<(Instant, Bytes)>,
    connection: Connection,
) {
    let local_sockid = connection.settings.local_sockid;
    let mut socket = socket;
    let mut input_data = input_data.fuse();
    let mut output_data = output_data;
    let mut connection = DuplexConnection::new(connection);
    while connection.is_open() {
        if connection.should_update_statistics(Instant::now()) {
            let _ = statistics_sender.send(connection.statistics().clone());
        }

        while let Some(packet) = connection.next_packet(Instant::now()) {
            if let Err(e) = socket.send(packet).await {
                error!("Error while sending packet: {:?}", e); // TODO: real error handling
            }
        }

        while let Some(data) = connection.next_data(Instant::now()) {
            if output_data.is_closed() {
                continue;
            }
            if let Err(e) = output_data.send(data).await {
                error!("Error while releasing packet {:?}", e);
            }
        }

        let timeout = connection.check_timers(Instant::now());
        let timeout_fut = async {
            let now = Instant::now();
            trace!(
                "{:?} scheduling wakeup at {:?}",
                local_sockid,
                TimeSpan::from_interval(timeout, now),
            );
            sleep_until(timeout.into()).await
        };

        let input = select! {
            // one of the entities requested wakeup
            _ = timeout_fut.fuse() => Input::Timer,
            // new packet received
            packet = socket.receive().fuse() =>
                Input::Packet(packet),
            // new packet queued
            data = input_data.next() => {
                Input::Data(data)
            }
        };

        match input {
            Input::Packet(packet) => connection.handle_packet_input(Instant::now(), packet),
            Input::Data(data) => connection.handle_data_input(Instant::now(), data),
            _ => {}
        }
    }
    if let Err(e) = output_data.close().await {
        error!("Error while closing data output stream {:?}", e);
    }
}

async fn run_input_loop(
    socket: PacketSocket,
    statistics_sender: watch::Sender<SocketStatistics>,
    output_data: Sender<(Instant, Bytes)>,
    input_data: Receiver<(Instant, Bytes)>,
    connection: Connection,
) {
    let mut socket = socket;
    let mut input_data = input_data.fuse();
    let mut output_data = output_data;
    let mut connection = DuplexConnection::new(connection);
    let mut input = Input::Timer;
    loop {
        let now = Instant::now();
        input = match connection.handle_input(now, input) {
            Action::Close => break,
            Action::ReleaseData(data) => {
                if !output_data.is_closed() {
                    if let Err(e) = output_data.send(data).await {
                        error!("Error while releasing data {:?}", e);
                    }
                }
                Input::DataReleased
            }
            Action::SendPacket(packet) => {
                if let Err(e) = socket.send(packet).await {
                    error!("Error while seding packet: {:?}", e); // TODO: real error handling
                }
                Input::PacketSent
            }
            Action::UpdateStatistics(statistics) => {
                let _ = statistics_sender.send(statistics.clone());
                Input::StatisticsUpdated
            }
            Action::WaitForData(wait) => {
                let timeout = now + wait;
                select! {
                    _ = sleep_until(timeout.into()).fuse() => Input::Timer,
                    packet = socket.receive().fuse() =>
                        Input::Packet(packet),
                    res = input_data.next() => {
                        Input::Data(res)
                    }
                }
            }
        }
    }
    if let Err(e) = output_data.close().await {
        error!("Error while closing data output stream {:?}", e);
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn statistics(&mut self) -> &mut (impl Stream<Item = SocketStatistics> + Clone) {
        &mut self.statistics
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(Pin::new(&mut self.output_data).poll_next(cx)).map(Ok))
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.input_data).poll_ready(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?))
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        self.input_data
            .start_send(item)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.input_data)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.input_data)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))
    }
}
