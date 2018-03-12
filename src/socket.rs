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

    pub fn build(self) -> Result<SrtSocket> {
        // start listening
        let sock = UdpSocket::bind(&self.local_addr)?;

        Ok(SrtSocket {
            start_time: Instant::now(),
            sock,
            buffer: {
                let tmp = Vec::new();
                tmp.resize(65536, b'\0');
                tmp
            },
        })
    }
}

pub struct SrtSocket {
    start_time: Instant, // TODO: should this be relative to handshake or creation
    sock: UdpSocket,
    buffer: Vec<u8>,
}

impl SrtSocket {
    pub fn get_timestamp(&self) -> i32 {
        // TODO: not sure if this should be us or ms
        (self.start_time.elapsed().as_secs() * 1_000_000
            + (self.start_time.elapsed().subsec_nanos() as u64 / 1_000)) as i32
    }

    pub fn send_packet(
        self,
        packet: &Packet,
        addr: SocketAddr,
    ) -> Box<Future<Item = SrtSocket, Error = Error>> {
        // serialize
        packet.serialize(&mut self.buffer);

        Box::new(
            self.sock
                .send_dgram(self.buffer, &addr)
                .map(move |(sock, buffer)| SrtSocket {
                    start_time: self.start_time,
                    sock,
                    buffer,
                }),
        )
    }

    pub fn recv_packet(self) -> Box<Future<Item = (SrtSocket, SocketAddr, Packet), Error = Error>> {
        Box::new(
            self.sock
                .recv_dgram(self.buffer)
                .and_then(move |(sock, buffer, size, addr)| {
                    let srt_socket = SrtSocket {
                        start_time: self.start_time,
                        sock,
                        buffer,
                    };

                    Ok((
                        srt_socket,
                        addr,
                        Packet::parse(Cursor::new(&srt_socket.buffer[0..size]))?,
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
                    let srt_socket = SrtSocket {
                        start_time: self.start_time,
                        sock,
                        buffer,
                    };

                    if let Some((size, addr)) = data {
                        // data was received, parse it
                        return Ok((
                            srt_socket,
                            Some((
                                addr,
                                Packet::parse(Cursor::new(&srt_socket.buffer[0..size]))?,
                            )),
                        ));
                    }

                    return Ok((srt_socket, None));
                },
            ),
        );
    }
}
