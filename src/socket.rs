use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{Error, ErrorKind, Result, Cursor};
use std::collections::VecDeque;

use tokio::net::{UdpSocket, RecvDgram, SendDgram};

use packet::Packet;

use bytes::BytesMut;

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
            queue: VecDeque::new(),
            future: SocketFuture::Recv(sock.recv_dgram(BytesMut::with_capacity(65536))),
        })
    }
}

pub enum SocketFuture {
    Send(SendDgram<BytesMut>),
    Recv(RecvDgram<BytesMut>),
}

pub struct SrtSocket {
    queue: VecDeque<(Packet, SocketAddr)>,
    future: SocketFuture,
}

impl Stream for SrtSocket {
    type Item = Packet;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Packet>, Error> {

        loop {

            let mut pack = None;

            let sock = match &mut self.future {
                &mut SocketFuture::Recv(ref mut recv) => {
                    let (sock, buff, n_bytes, from_addr) = try_ready!(recv.poll());

                    // parse the packet
                    pack = Some(Packet::parse(Cursor::new(buff.freeze().slice(0, n_bytes)))?);
                    
                    sock
                }
                &mut SocketFuture::Send(ref mut snd) => {
                    let (sock, _) = try_ready!(snd.poll());
                    sock
                }
            };

            // start the next op
            self.future = match self.queue.pop_front() {
                Some((pack, addr)) => {
                    // send the packet

                    // serialize the packet
                    let mut bytes = BytesMut::with_capacity(65536);
                    pack.serialize(&mut bytes);

                    // send it
                    SocketFuture::Send(sock.send_dgram(bytes, &addr))
                },
                None => {
                    // just receive
                    let mut bytes = BytesMut::with_capacity(65536);

                    SocketFuture::Recv(sock.recv_dgram(bytes))
                }
            };

            if let Some(p) = pack {
                return Ok(Async::Ready(Some(p)));
            }
        }
    }
}
