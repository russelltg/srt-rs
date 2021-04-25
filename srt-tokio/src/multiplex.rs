mod streamer_server;

pub use self::streamer_server::StreamerServer;

use std::{
    collections::HashMap,
    io::{self, Cursor},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use bytes::BytesMut;
use futures::{prelude::*, stream::unfold};

use log::{info, warn};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, Sender},
};
use tokio_stream::wrappers::ReceiverStream;

use crate::{tokio::create_bidrectional_srt, Packet, SocketId, SrtSocket};
use srt_protocol::{
    accesscontrol::StreamAcceptor,
    pending_connection::{listen::Listen, ConnInitSettings, ConnectionResult},
};

struct MultiplexState<A: StreamAcceptor> {
    sock: Arc<UdpSocket>,
    pending: HashMap<SocketAddr, Listen>,
    acceptor: A,
    conns: HashMap<SocketId, Sender<(Packet, SocketAddr)>>,
    init_settings: ConnInitSettings,
    recv_buffer: BytesMut,
}

impl<T: StreamAcceptor> MultiplexState<T> {
    async fn next_conn(&mut self) -> Result<Option<SrtSocket>, io::Error> {
        loop {
            self.sock.readable().await?;
            self.recv_buffer.clear();
            match self.sock.try_recv_buf_from(&mut self.recv_buffer) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
                Ok((bytes_read, from)) => {
                    let packet = Packet::parse(
                        &mut Cursor::new(&self.recv_buffer[..bytes_read]),
                        self.sock.local_addr().unwrap().is_ipv6(),
                    );
                    match packet {
                        Ok(packet) => {
                            if let Some(complete) = self.delegate_packet(packet, from).await? {
                                return Ok(Some(complete));
                            }
                        }
                        Err(e) => warn!("Packet parsing error: {}", e),
                    }
                }
            }
        }
    }

    async fn send_packet(&mut self, pack: &Packet, to: SocketAddr) -> Result<(), io::Error> {
        self.recv_buffer.clear();
        pack.serialize(&mut self.recv_buffer);
        self.sock.send_to(&self.recv_buffer, to).await?;

        Ok(())
    }

    async fn delegate_packet(
        &mut self,
        pack: Packet,
        from: SocketAddr,
    ) -> Result<Option<SrtSocket>, io::Error> {
        // fast path--an already established connection
        let dst_sockid = pack.dest_sockid();
        if let Some(chan) = self.conns.get_mut(&dst_sockid) {
            if let Err(_send_err) = chan.send((pack, from)).await {
                self.conns.remove(&dst_sockid);
            }
            return Ok(None);
        }

        let init_settings = &self.init_settings; // explicitly only borrow this field
        let listen = self
            .pending
            .entry(from)
            .or_insert_with(|| Listen::new(init_settings.copy_randomize()));

        // already started connection?
        let conn = match listen.handle_packet((pack, from), Instant::now(), &mut self.acceptor) {
            ConnectionResult::SendPacket((packet, addr)) => {
                self.send_packet(&packet, addr).await?;
                return Ok(None);
            }
            ConnectionResult::Reject(pa, rej) => {
                if let Some((packet, to)) = pa {
                    self.send_packet(&packet, to).await?;
                }
                info!("Rejected connection from {}: {}", from, rej);
                self.pending.remove(&from);
                return Ok(None);
            }
            ConnectionResult::NotHandled(e) => {
                warn!("{:?}", e);
                return Ok(None);
            }
            ConnectionResult::NoAction => return Ok(None),
            ConnectionResult::Connected(pa, c) => {
                if let Some((packet, to)) = pa {
                    self.send_packet(&packet, to).await?;
                }
                c
            }
        };

        let (s, r) = mpsc::channel(100);

        self.conns.insert(conn.settings.local_sockid, s);

        self.pending.remove(&from); // remove from pending connections, it's been resolved
        return Ok(Some(create_bidrectional_srt(
            self.sock.clone(),
            ReceiverStream::new(r),
            conn,
        )));
    }
}

pub async fn multiplex(
    addr: SocketAddr,
    init_settings: ConnInitSettings,
    acceptor: impl StreamAcceptor,
) -> Result<impl Stream<Item = Result<SrtSocket, io::Error>>, io::Error> {
    Ok(unfold(
        MultiplexState {
            sock: Arc::new(UdpSocket::bind(addr).await?),
            pending: HashMap::new(),
            acceptor,
            conns: HashMap::new(),
            recv_buffer: BytesMut::with_capacity(1024),
            init_settings,
        },
        |mut state| async move {
            match state.next_conn().await {
                Err(e) => Some((Err(e), state)),
                Ok(Some(c)) => Some((Ok(c), state)),
                Ok(None) => None,
            }
        },
    ))
}
