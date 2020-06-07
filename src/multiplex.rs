mod streamer_server;

pub use self::streamer_server::StreamerServer;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use futures::future::{pending, select_all};
use futures::prelude::*;
use futures::select;
use futures::stream::unfold;

use log::warn;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use crate::channel::Channel;
use crate::pending_connection::{
    listen::{Listen, ListenState},
    ConnInitSettings,
};
use crate::protocol::handshake::Handshake;
use crate::{Connection, Packet, PacketCodec, SocketID};

pub type PackChan = Channel<(Packet, SocketAddr)>;

struct MultiplexState {
    sock: UdpFramed<PacketCodec>,
    pending: HashMap<SocketAddr, Listen>,
    conns: HashMap<SocketID, PackChan>,
    init_settings: ConnInitSettings,
}

#[allow(clippy::large_enum_variant)]
enum Action {
    Delegate(Packet, SocketAddr),
    Remove(SocketID),
    Send((Packet, SocketAddr)),
}

impl MultiplexState {
    async fn next_conn(&mut self) -> Result<Option<(Connection, PackChan)>, io::Error> {
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
            let action = select! {
                new_pack = self.sock.next().fuse() => {
                    match new_pack {
                        None => return Ok(None),
                        Some(Err(e)) => return Err(io::Error::from(e)),
                        Some(Ok((pack, from))) => {
                            Action::Delegate(pack, from)
                        }
                    }
                },
                ((sockid, pack), _, _) = joined.fuse() => {
                    match pack {
                        None  => { Action::Remove(*sockid) }
                        Some(pack) => { Action::Send(pack)  }
                    }
                },
            };

            match action {
                Action::Delegate(pack, from) => {
                    if let Some(complete) = self.delegate_packet(pack, from).await? {
                        return Ok(Some(complete));
                    }
                }
                Action::Remove(sockid) => {
                    self.conns.remove(&sockid);
                }
                Action::Send(pack) => {
                    self.sock.send(pack).await?;
                }
            }
        }
    }

    async fn delegate_packet(
        &mut self,
        pack: Packet,
        from: SocketAddr,
    ) -> Result<Option<(Connection, PackChan)>, io::Error> {
        // fast path--an already established connection
        if let Some(chan) = self.conns.get_mut(&pack.dest_sockid()) {
            let dst_sockid = pack.dest_sockid();
            if let Err(_send_err) = chan.send((pack, from)).await {
                self.conns.remove(&dst_sockid);
            }
            return Ok(None);
        }

        // new connection?
        let this_conn_settings = self.init_settings.clone();
        let listen = self
            .pending
            .entry(from)
            .or_insert_with(|| Listen::new(this_conn_settings.copy_randomize()));

        // already started connection?
        match listen.handle_packet((pack, from)) {
            Ok(Some(pa)) => self.sock.send(pa).await?,
            Err(e) => warn!("{:?}", e),
            _ => {}
        }
        if let ListenState::Connected(resp_handshake, settings) = listen.state().clone() {
            let (s, r) = Channel::channel(100);

            self.conns.insert(settings.local_sockid, r);

            let conn = Connection {
                settings,
                handshake: Handshake::Listener(resp_handshake.control_type),
            };
            self.pending.remove(&from); // remove from pending connections, it's been resolved
            return Ok(Some((conn, s)));
        }
        Ok(None)
    }
}

pub async fn multiplex(
    addr: SocketAddr,
    init_settings: ConnInitSettings,
) -> Result<impl Stream<Item = Result<(Connection, PackChan), io::Error>>, io::Error> {
    Ok(unfold(
        MultiplexState {
            sock: UdpFramed::new(UdpSocket::bind(addr).await?, PacketCodec),
            pending: HashMap::new(),
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
