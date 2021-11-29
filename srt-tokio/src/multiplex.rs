use std::{collections::HashMap, io, net::SocketAddr, time::Instant};

use futures::{channel::mpsc, prelude::*, stream::unfold};
use log::{info, warn};

use srt_protocol::{
    packet::*,
    protocol::pending_connection::{listen::Listen, ConnectionResult},
    settings::*,
};

use crate::net::PacketSocket;
use crate::{socket::create_bidrectional_srt, SrtSocket};

pub use self::streamer_server::StreamerServer;

mod streamer_server;

struct MultiplexState<A: StreamAcceptor> {
    socket: PacketSocket,
    pending: HashMap<SocketAddr, Listen>,
    acceptor: A,
    conns: HashMap<SocketId, mpsc::Sender<ReceivePacketResult>>,
    init_settings: ConnInitSettings,
}

impl<T: StreamAcceptor> MultiplexState<T> {
    async fn next_conn(&mut self) -> Result<Option<SrtSocket>, io::Error> {
        loop {
            match self.socket.receive().await {
                Ok(packet) => {
                    if let Some(complete) = self.delegate_packet(packet).await? {
                        return Ok(Some(complete));
                    }
                }
                Err(PacketParseError::Io(e)) => return Err(e),
                Err(e) => warn!("Packet parsing error: {}", e),
            }
        }
    }

    async fn delegate_packet(
        &mut self,
        packet: (Packet, SocketAddr),
    ) -> Result<Option<SrtSocket>, io::Error> {
        let from = packet.1;
        // fast path--an already established connection
        let dst_sockid = packet.0.dest_sockid();
        if let Some(chan) = self.conns.get_mut(&dst_sockid) {
            if let Err(_send_err) = chan.send(Ok(packet)).await {
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
        let conn = match listen.handle_packet(Ok(packet), Instant::now(), &mut self.acceptor) {
            ConnectionResult::SendPacket(packet) => {
                self.socket.send(packet).await?;
                return Ok(None);
            }
            ConnectionResult::Reject(pa, rej) => {
                if let Some(packet) = pa {
                    self.socket.send(packet).await?;
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
                if let Some(packet) = pa {
                    self.socket.send(packet).await?;
                }
                c
            }
            ConnectionResult::Failure(error) => return Err(error),
        };

        let (s, socket) = self.socket.clone_channel(100);

        self.conns.insert(conn.settings.local_sockid, s);

        self.pending.remove(&from); // remove from pending connections, it's been resolved

        Ok(Some(create_bidrectional_srt(socket, conn)))
    }
}

pub async fn multiplex(
    addr: SocketAddr,
    init_settings: ConnInitSettings,
    acceptor: impl StreamAcceptor,
) -> Result<impl Stream<Item = Result<SrtSocket, io::Error>>, io::Error> {
    Ok(unfold(
        MultiplexState {
            socket: PacketSocket::bind(addr, 1024 * 1024).await?,
            pending: HashMap::new(),
            acceptor,
            conns: HashMap::new(),
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
