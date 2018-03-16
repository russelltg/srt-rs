use std::net::SocketAddr;
use std::io::{Cursor, Error, Result};
use std::iter::repeat;
use std::time::{Duration, Instant};
use std::boxed::Box;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

use packet::Packet;
use pending_connection::PendingConnection;
use receiver::Receiver;
use recv_dgram_timeout::RecvDgramTimeout;

use bytes::{BufMut, Bytes, BytesMut};

use futures::prelude::*;

/// Struct to build sockets
pub struct SrtSocketBuilder {
    local_addr: SocketAddr,
    connect_addr: Option<SocketAddr>,
}

impl SrtSocketBuilder {
    /// Create a SrtSocketBuilder
    /// If you don't want to bind to a port, pass 0.0.0.0:0
    pub fn new(local_addr: SocketAddr) -> Self {
        SrtSocketBuilder {
            local_addr,
            connect_addr: None,
        }
    }

    /// Set the address to connect to
    pub fn connet_to(mut self, connet_addr: SocketAddr) -> Self {
        self.connect_addr = Some(connet_addr);

        self
    }

    pub fn build(self) -> Result<PendingConnection> {
        let socket = SrtSocket {
            sock: UdpSocket::bind(&self.local_addr)?,
            buffer: {
                let mut tmp = Vec::new();
                tmp.resize(65536, b'\0');
                tmp
            },
        };

        Ok(match self.connect_addr {
            Some(addr) => PendingConnection::connect(socket, addr),
            None => PendingConnection::listen(socket),
        })
    }
}

pub struct SrtSocket {
    sock: UdpSocket,
    buffer: Vec<u8>,
}

impl SrtSocket {
    pub fn send_packet(
        mut self,
        packet: &Packet,
        addr: &SocketAddr,
    ) -> Box<Future<Item = SrtSocket, Error = Error>> {
        // serialize
        packet.serialize(&mut self.buffer);

        Box::new(
            self.sock
                .send_dgram(self.buffer, addr)
                .map(move |(sock, buffer)| SrtSocket { sock, buffer }),
        )
    }

    pub fn recv_packet(self) -> Box<Future<Item = (SrtSocket, SocketAddr, Packet), Error = Error>> {
        Box::new(
            self.sock
                .recv_dgram(self.buffer)
                .and_then(move |(sock, buffer, size, addr)| {
                    let srt_socket = SrtSocket { sock, buffer };

                    let pack = Packet::parse(Cursor::new(&srt_socket.buffer[0..size]))?;

                    Ok((
                        srt_socket,
                        addr,
                        pack,
                    ))
                }),
        )
    }

    pub fn recv_packet_timeout(
        self,
        timeout: Duration,
    ) -> Box<Future<Item = (SrtSocket, Option<(SocketAddr, Packet)>), Error = Error>> {
        return Box::new(
            RecvDgramTimeout::new(self.sock, timeout, self.buffer).and_then(
                move |(sock, buffer, data)| {
                    let srt_socket = SrtSocket { sock, buffer };


                    if let Some((size, addr)) = data {
                        let pack = Packet::parse(Cursor::new(&srt_socket.buffer[0..size]))?;
                        // data was received, parse it
                        return Ok((
                            srt_socket,
                            Some((
                                addr,
                                pack,
                            )),
                        ));
                    }

                    return Ok((srt_socket, None));
                },
            ),
        );
    }
}
