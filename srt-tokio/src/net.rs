use std::{
    error,
    fmt::{Debug, Display, Formatter},
    io::{self, Cursor, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use futures::channel::mpsc::Receiver;
use futures::{channel::mpsc, prelude::*};
use srt_protocol::packet::{Packet, ReceivePacketResult};
use tokio::net::{ToSocketAddrs, UdpSocket};

pub struct PacketSocket {
    socket: Arc<UdpSocket>,
    stream: Option<mpsc::Receiver<ReceivePacketResult>>,
    buffer: BytesMut,
}

impl PacketSocket {
    pub async fn bind<A: ToSocketAddrs>(
        address: A,
        buffer_capacity: usize,
    ) -> Result<Self, io::Error> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        Ok(Self::from_socket(socket, buffer_capacity))
    }

    pub fn from_socket(socket: Arc<UdpSocket>, buffer_capacity: usize) -> Self {
        Self {
            socket,
            stream: None,
            buffer: BytesMut::with_capacity(buffer_capacity),
        }
    }

    pub fn clone_channel(
        &self,
        channel_buffer: usize,
    ) -> (mpsc::Sender<ReceivePacketResult>, Self) {
        let (packet_sender, packet_receiver) = mpsc::channel(channel_buffer);
        (
            packet_sender,
            Self {
                socket: self.socket.clone(),
                stream: Some(packet_receiver),
                buffer: BytesMut::with_capacity(self.buffer.capacity()),
            },
        )
    }

    pub async fn send(&mut self, packet: (Packet, SocketAddr)) -> Result<usize, io::Error> {
        self.buffer.clear();
        packet.0.serialize(&mut self.buffer);
        self.socket.send_to(&self.buffer, packet.1).await
    }

    pub async fn receive(&mut self) -> ReceivePacketResult {
        match self.stream.as_mut() {
            Some(stream) => Self::stream_receive(stream).await,
            None => self.socket_receive().await,
        }
    }

    async fn stream_receive(stream: &mut Receiver<ReceivePacketResult>) -> ReceivePacketResult {
        stream.next().await.unwrap_or_else(|| {
            Err(io::Error::new(ErrorKind::NotConnected, PacketStreamClosedError).into())
        })
    }

    async fn socket_receive(&mut self) -> ReceivePacketResult {
        loop {
            self.socket.readable().await?;
            self.buffer.clear();
            return match self.socket.try_recv_buf_from(&mut self.buffer) {
                Ok((size, from)) => self.parse(size, from),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => Err(e.into()),
            };
        }
    }

    fn parse(&mut self, size: usize, from: SocketAddr) -> ReceivePacketResult {
        let packet = Packet::parse(
            &mut Cursor::new(&self.buffer[0..size]),
            self.socket.local_addr()?.is_ipv6(),
        )?;
        Ok((packet, from))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PacketStreamClosedError;

impl Display for PacketStreamClosedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "packet stream was closed")
    }
}

impl error::Error for PacketStreamClosedError {}
