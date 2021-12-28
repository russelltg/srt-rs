use std::{
    convert::TryFrom,
    error,
    fmt::{Debug, Display, Formatter},
    io::{self, Cursor, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use futures::channel::mpsc::Receiver;
use futures::{channel::mpsc, prelude::*};
use socket2::{Domain, Protocol, Socket, Type};
use srt_protocol::packet::{Packet, ReceivePacketResult};
use tokio::net::UdpSocket;

use crate::options::*;

pub async fn bind_socket(options: &SocketOptions) -> Result<UdpSocket, io::Error> {
    let socket = Socket::new(
        if options.connect.local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    let send_buffer_size = usize::try_from(options.connect.udp_send_buffer_size.0).unwrap();
    let recv_buffer_size = usize::try_from(options.connect.udp_recv_buffer_size.0).unwrap();

    socket.set_nonblocking(true)?; // required for passing to tokio
    socket.set_recv_buffer_size(recv_buffer_size)?;
    socket.set_send_buffer_size(send_buffer_size)?;
    socket.bind(&options.connect.local.into())?;

    UdpSocket::from_std(socket.into())
}

pub async fn lookup_remote_host(remote: &SocketAddress) -> Result<SocketAddr, io::Error> {
    use SocketHost::*;
    let mut remote_address = match &remote.host {
        Domain(domain) => tokio::net::lookup_host(domain)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, OptionsError::InvalidRemoteAddress)
            })?,
        Ipv4(ipv4) => SocketAddr::new((*ipv4).into(), 0),
        Ipv6(ipv6) => SocketAddr::new((*ipv6).into(), 0),
    };
    if remote_address.port() == 0 {
        remote_address.set_port(remote.port);
    }
    Ok(remote_address)
}

pub struct PacketSocket {
    socket: Arc<UdpSocket>,
    stream: Option<mpsc::Receiver<ReceivePacketResult>>,
    buffer: BytesMut,
}

impl PacketSocket {
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
