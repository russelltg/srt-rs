use std::{
    io,
    time::{Duration, Instant},
};

use futures::{prelude::*, select};
use log::{debug, warn};
use tokio::time::interval;

use srt_protocol::{
    connection::Connection,
    options::*,
    protocol::pending_connection::{rendezvous::Rendezvous, ConnectionResult},
    settings::*,
};

use crate::net::{lookup_remote_host, PacketSocket};

pub async fn bind_with(
    mut socket: PacketSocket,
    options: Valid<RendezvousOptions>,
) -> Result<(PacketSocket, Connection), io::Error> {
    let local_addr = options.socket.connect.local;
    let remote_public = lookup_remote_host(&options.remote).await?;
    let starting_seqno = rand::random();
    let init_settings: ConnInitSettings = options.socket.clone().into();
    let socket_id = init_settings.local_sockid;

    let mut tick_interval = interval(Duration::from_millis(100));
    let mut rendezvous = Rendezvous::new(local_addr, remote_public, init_settings, starting_seqno);
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => rendezvous.handle_tick(now.into()),
            packet = socket.receive().fuse() => rendezvous.handle_packet(packet, Instant::now()),
        };

        debug!("{:?}:rendezvous - {:?}", socket_id, result);
        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                let _ = socket.send(packet).await?;
            }
            NotHandled(e) => {
                warn!("rendezvous {:?} error: {}", socket_id, e);
            }
            Reject(_, _) => todo!(),
            Connected(p, connection) => {
                if let Some(packet) = p {
                    let _ = socket.send(packet).await?;
                }
                return Ok((socket, connection));
            }
            NoAction => {}
            RequestAccess(_) => {}
            Failure(error) => return Err(error),
        }
    }
}
