use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use bytes::Bytes;
use futures::{
    channel::mpsc::{self, Receiver, Sender},
    prelude::*,
    ready, select,
};
use log::{error, trace};
use srt_protocol::{
    connection::{Action, Connection, ConnectionSettings, DuplexConnection, Input},
    packet::*,
    statistics::SocketStatistics,
};
use tokio::{net::UdpSocket, sync::watch, time::sleep_until};
use tokio_stream::wrappers::WatchStream;

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

    statistics: WatchStream<SocketStatistics>,

    settings: ConnectionSettings,
}

/// This spawns two new tasks:
/// 1. Receive packets and send them to either the sender or the receiver through
///    a channel
/// 2. Take outgoing packets and send them on the socket
pub fn create_bidrectional_srt(
    socket: Arc<UdpSocket>,
    packets: impl Stream<Item = (Packet, SocketAddr)> + Unpin + Send + 'static,
    conn: Connection,
) -> SrtSocket {
    let (output_data_sender, output_data_receiver) = mpsc::channel(128);
    let (input_data_sender, input_data_receiver) = mpsc::channel(128);
    let (statistics_sender, statistics_receiver) = watch::channel(SocketStatistics::new());
    let statistics_receiver = WatchStream::new(statistics_receiver);
    let conn_copy = conn.clone();
    tokio::spawn(async move {
        // Using run_input_loop breaks a couple of the stransmit_interop tests.
        // Both stransmit_decrypt and stransmit_server run indefinitely. For now,
        // run_handler_loop exclusively, until a fix is found or an API decision
        // is reached.
        if Instant::now().elapsed().as_nanos() != 0 {
            run_handler_loop(
                socket,
                packets,
                statistics_sender,
                output_data_sender,
                input_data_receiver,
                conn_copy,
            )
            .await;
        } else {
            run_input_loop(
                socket,
                packets,
                statistics_sender,
                output_data_sender,
                input_data_receiver,
                conn_copy,
            )
            .await;
        }
    });

    SrtSocket {
        statistics: statistics_receiver,
        output_data: output_data_receiver,
        input_data: input_data_sender,
        settings: conn.settings,
    }
}

async fn run_handler_loop(
    socket: Arc<UdpSocket>,
    packets: impl Stream<Item = (Packet, SocketAddr)> + Unpin + Send + 'static,
    statistics_sender: watch::Sender<SocketStatistics>,
    output_data: mpsc::Sender<(Instant, Bytes)>,
    input_data: mpsc::Receiver<(Instant, Bytes)>,
    connection: Connection,
) {
    let local_sockid = connection.settings.local_sockid;
    let mut input_data = input_data.fuse();
    let mut output_data = output_data;
    let mut packets = packets.fuse();
    let mut connection = DuplexConnection::new(connection);
    let mut serialize_buffer = Vec::new();
    while connection.is_open() {
        if connection.should_update_statistics(Instant::now()) {
            let _ = statistics_sender.send(connection.statistics().clone());
        }

        while let Some((packet, addr)) = connection.next_packet(Instant::now()) {
            serialize_buffer.clear();
            packet.serialize(&mut serialize_buffer);
            if let Err(e) = socket.send_to(&serialize_buffer, addr).await {
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
            packet = packets.next() =>
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
    socket: Arc<UdpSocket>,
    packets: impl Stream<Item = (Packet, SocketAddr)> + Unpin + Send + 'static,
    statistics_sender: watch::Sender<SocketStatistics>,
    output_data: Sender<(Instant, Bytes)>,
    input_data: Receiver<(Instant, Bytes)>,
    connection: Connection,
) {
    let mut input_data = input_data.fuse();
    let mut output_data = output_data;
    let mut packets = packets.fuse();
    let mut connection = DuplexConnection::new(connection);
    let mut input = Input::Timer;
    let mut serialize_buffer = Vec::new();
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
            Action::SendPacket((packet, address)) => {
                serialize_buffer.clear();
                packet.serialize(&mut serialize_buffer);
                if let Err(e) = socket.send_to(&serialize_buffer, address).await {
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
                    packet = packets.next() =>
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

    pub fn stats(&mut self) -> &mut impl Stream<Item = SocketStatistics> {
        &mut self.statistics
    }

    pub fn statistics(&mut self) -> &mut impl Stream<Item = SocketStatistics> {
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
