use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{Cursor, Error, ErrorKind, Result};
use std::iter::repeat;
use std::sync::mpsc::{channel, Receiver, TryRecvError};

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

use packet::Packet;

use bytes::{BufMut, BytesMut};

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

        let mut bytes = BytesMut::with_capacity(65536);

        // TODO: there should be a cleaner way to do this,
        // if this doesn't happen the len is zero so no data is read
        let vec: Vec<_> = repeat(b'\0').take(65535).collect();
        bytes.put(&vec);

        // create the queue
        // TODO: do something with tx
        let (_, rx) = channel();

        Ok(SrtSocket {
            queue: rx,
            future: SocketFuture::Recv(sock.recv_dgram(bytes)),
        })
    }
}

// Represents either future that the socket can hold
enum SocketFuture {
    Send(SendDgram<BytesMut>),
    Recv(RecvDgram<BytesMut>),
}

pub struct SrtSocket {
    queue: Receiver<(Packet, SocketAddr)>,
    future: SocketFuture,
}

impl Stream for SrtSocket {
    type Item = Packet;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Packet>, Error> {
        loop {
            let mut pack = None;

            let (sock, buff) = match &mut self.future {
                &mut SocketFuture::Recv(ref mut recv) => {
                    let (sock, mut buff, n_bytes, from_addr) = try_ready!(recv.poll());

                    // parse the packet
                    pack = Some(Packet::parse(Cursor::new(&buff.as_mut()[0..n_bytes]))?);

                    (sock, buff)
                }
                &mut SocketFuture::Send(ref mut snd) => {
                    let (sock, mut buff) = try_ready!(snd.poll());

                    (sock, buff)
                }
            };

            // start the next op
            self.future = match self.queue.try_recv() {
                Ok((pack, addr)) => {
                    // send the packet

                    // serialize the packet
                    let mut bytes = BytesMut::with_capacity(65536);
                    pack.serialize(&mut bytes);

                    // send it
                    SocketFuture::Send(sock.send_dgram(bytes, &addr))
                }
                // If it's either disconnected or empty just receive
                Err(_) => {
                    // just receive
                    SocketFuture::Recv(sock.recv_dgram(buff))
                }
            };

            if let Some(p) = pack {
                return Ok(Async::Ready(Some(p)));
            }
        }
    }
}
