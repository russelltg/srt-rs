mod streamer_server;

pub use self::streamer_server::StreamerServer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use futures::future::{pending, select_all};
use futures::prelude::*;
use futures::select;
use futures::stream::unfold;

use failure::Error;
use log::warn;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use crate::channel::Channel;
use crate::pending_connection::listen::{Listen, ListenConfiguration, ListenState};
use crate::protocol::handshake::Handshake;
use crate::{Connection, Packet, PacketCodec, SocketID};

pub type PackChan = Channel<(Packet, SocketAddr)>;

struct MultiplexState {
    sock: UdpFramed<PacketCodec>,
    pending: HashMap<SocketAddr, Listen>,
    conns: HashMap<SocketID, PackChan>,
    latency: Duration,
}

impl MultiplexState {
    async fn next_conn(&mut self) -> Result<Option<(Connection, PackChan)>, Error> {
        loop {
            // impl Future<Output = (Packet, SocketAddr)
            let conns = &mut self.conns;
            let joined = async {
                // select_all panics if there are no elements, but pending is the correct behavior
                if conns.is_empty() {
                    pending().await
                } else {
                    select_all(
                        conns
                            .iter_mut()
                            .map(|(sid, chan)| chan.next().map(move |p| (sid, p))),
                    )
                    .await
                }
            };
            select! {
                new_pack = self.sock.next().fuse() => {
                    match new_pack {
                        None => return Ok(None),
                        Some(Err(e)) => return Err(e),
                        Some(Ok((pack, from))) => {
                            if let Some(complete) = self.delegate_packet(pack, from).await? {
                                return Ok(Some(complete));
                            }
                        }
                    }
                },
                ((&sockid, pack), _, _) = joined.fuse() => {
                    match pack {
                        None => { self.conns.remove(&sockid); }
                        Some(Ok(pack)) => { self.sock.send(pack).await?; }
                        Some(Err(e)) => return Err(e),
                    }
                },
            };
        }
    }

    async fn delegate_packet(
        &mut self,
        pack: Packet,
        from: SocketAddr,
    ) -> Result<Option<(Connection, PackChan)>, Error> {
        // fast path--an already established connection
        if let Some(chan) = self.conns.get_mut(&pack.dest_sockid()) {
            chan.send((pack, from)).await?;
            return Ok(None);
        }

        // new connection?
        let tsbpd_latency = self.latency;
        let listen = self.pending.entry(from).or_insert_with(|| {
            Listen::new(ListenConfiguration {
                local_socket_id: rand::random(),
                tsbpd_latency,
            })
        });

        // already started connection?
        match listen.handle_packet((pack, from)) {
            Ok(Some(pa)) => self.sock.send(pa).await?,
            Err(e) => warn!("{:?}", e),
            _ => {}
        }
        if let ListenState::Connected(resp_handshake, settings) = listen.state().clone() {
            let (s, r) = Channel::channel(100);

            self.pending.remove(&from); // remove from pending connections, it's been resolved
            self.conns.insert(settings.local_sockid, r);
            return Ok(Some((
                Connection {
                    settings,
                    handshake: Handshake::Listener(resp_handshake.control_type),
                },
                s,
            )));
        }
        Ok(None)
    }
}

pub async fn multiplex(
    addr: SocketAddr,
    latency: Duration,
) -> Result<impl Stream<Item = Result<(Connection, PackChan), Error>>, Error> {
    Ok(unfold(
        MultiplexState {
            sock: UdpFramed::new(UdpSocket::bind(addr).await?, PacketCodec),
            pending: HashMap::new(),
            conns: HashMap::new(),
            latency,
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
