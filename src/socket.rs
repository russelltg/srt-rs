use std::net::SocketAddr;
use std::io::{Cursor, Error, Result};
use std::time::Duration;
use std::boxed::Box;

use tokio::net::UdpSocket;
use rand::{thread_rng, Rng};

use packet::Packet;
use pending_connection::PendingConnection;
use recv_dgram_timeout::RecvDgramTimeout;

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
        trace!("Listening on {:?}", self.local_addr);

        let socket = SrtSocket {
            id: SrtSocketBuilder::gen_sockid(),
            sock: UdpSocket::bind(&self.local_addr)?,
            buffer: {
                let mut tmp = Vec::new();
                tmp.reserve(65536);
                tmp
            },
        };

        Ok(match self.connect_addr {
            Some(addr) => PendingConnection::connect(socket, addr),
            None => PendingConnection::listen(socket),
        })
    }

    pub fn build_raw(self) -> Result<SrtSocket> {
        Ok(SrtSocket {
            id: SrtSocketBuilder::gen_sockid(),
            sock: UdpSocket::bind(&self.local_addr)?,
            buffer: {
                let mut tmp = Vec::new();
                tmp.reserve(65536);
                tmp
            },
        })
    }

    pub fn gen_sockid() -> i32 {
        thread_rng().gen::<i32>()
    }
}

pub struct SrtSocket {
    sock: UdpSocket,
    buffer: Vec<u8>,
    id: i32,
}

impl SrtSocket {
    pub fn send_packet(
        mut self,
        packet: &Packet,
        addr: &SocketAddr,
    ) -> Box<Future<Item = SrtSocket, Error = Error>> {
        // serialize
        self.buffer.resize(0, b'\0');
        packet.serialize(&mut self.buffer);

        let id = self.id;
        Box::new(
            self.sock
                .send_dgram(self.buffer, addr)
                .map(move |(sock, buffer)| SrtSocket { id, sock, buffer }),
        )
    }

    pub fn recv_packet(
        mut self,
    ) -> Box<Future<Item = (SrtSocket, SocketAddr, Packet), Error = (SrtSocket, Error)>> {
        self.buffer.resize(65536, b'\0');

        let id = self.id;
        Box::new(
            self.sock
                .recv_dgram(self.buffer)
                .map_err(|e| panic!(e))
                .and_then(move |(sock, buffer, size, addr)| {
                    let srt_socket = SrtSocket { id, sock, buffer };

                    let pack = match Packet::parse(Cursor::new(&srt_socket.buffer[0..size])) {
                        Err(e) => return Err((srt_socket, e)),
                        Ok(p) => p,
                    };

                    Ok((srt_socket, addr, pack))
                }),
        )
    }

    pub fn recv_packet_timeout(
        self,
        timeout: Duration,
    ) -> Box<Future<Item = (SrtSocket, Option<(SocketAddr, Packet)>), Error = (SrtSocket, Error)>>
    {
        let id = self.id;

        return Box::new(
            RecvDgramTimeout::new(self.sock, timeout, self.buffer)
                .map_err(|e| {
                    // all these are irrecoverable, so don't bother
                    panic!(e)
                })
                .and_then(move |(sock, buffer, data)| {
                    let srt_socket = SrtSocket { id, sock, buffer };

                    if let Some((size, addr)) = data {
                        // data was received, parse it
                        let pack = match Packet::parse(Cursor::new(&srt_socket.buffer[0..size])) {
                            Err(e) => return Err((srt_socket, e)),
                            Ok(p) => p,
                        };
                        return Ok((srt_socket, Some((addr, pack))));
                    }

                    return Ok((srt_socket, None));
                }),
        );
    }

    pub fn id(&self) -> i32 {
        self.id
    }
}
