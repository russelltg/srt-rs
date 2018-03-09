use std::net::SocketAddr;
use std::io::{Cursor, Error, Result};
use std::iter::repeat;
use std::time::Instant;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

use packet::Packet;
use pending_connection::PendingConnection;
use receiver::Receiver;

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

        let mut bytes = {
            let tmp = BytesMut::with_capacity(65536);

            // TODO: there should be a cleaner way to do this,
            // if this doesn't happen the len is zero so no data is read
            let vec: Vec<_> = repeat(b'\0').take(65535).collect();
            tmp.put(&vec);

            tmp
        };

        let sock = SrtSocket {
            future: SocketFuture::Recv(sock.recv_dgram(bytes)),
            start_time: Instant::now(),
        };

        match self.connect_addr {
            Some(addr) => Ok(PendingConnection::connect(addr)),
            None => Ok(PendingConnection::listen()),
        }
    }
}

// Represents either future that the socket can hold
enum SocketFuture {
    Send(SendDgram<BytesMut>),
    Recv(RecvDgram<BytesMut>),
}

enum SocketState {
    Connecting(PendingConnection),
    Receiver(Receiver),
}

pub struct SrtSocket {
    future: SocketFuture,
    start_time: Instant, // TODO: should this be relative to handshake or creation
    state: SocketState,
}

impl SrtSocket {
    pub fn get_timestamp(&self) -> i32 {
        // TODO: not sure if this shold be us or ms
        (self.start_time.elapsed().as_secs() * 1_000_000
            + (self.start_time.elapsed().subsec_nanos() as u64 / 1_000)) as i32
    }
}

impl Stream for SrtSocket {
    type Item = (Packet, SocketAddr);
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<(Packet, SocketAddr)>, Error> {
        loop {
            let mut ret = None;

            let (sock, buff) = match &mut self.future {
                &mut SocketFuture::Recv(ref mut recv) => {
                    let (sock, mut buff, n_bytes, addr) = try_ready!(recv.poll());

                    // parse the packet
                    ret = Some((
                        Packet::parse(Cursor::new(&buff.as_mut()[0..n_bytes]))?,
                        addr,
                    ));

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
                    println!("Sending packet {:?} to {:?}", pack, addr);
                    SocketFuture::Send(sock.send_dgram(bytes, &addr))
                }
                // If it's either disconnected or empty just receive
                Err(_) => SocketFuture::Recv(sock.recv_dgram(buff)),
            };

            if let Some(p) = ret {
                return Ok(Async::Ready(Some(p)));
            }
        }
    }
}
