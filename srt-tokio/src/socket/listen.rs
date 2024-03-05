use std::{io, time::Instant};

use log::{debug, warn};

use srt_protocol::{
    connection::Connection,
    options::*,
    protocol::pending_connection::{listen::Listen, ConnectionResult},
    settings::*,
};

use crate::net::PacketSocket;

pub async fn bind_with(
    mut socket: PacketSocket,
    options: Valid<ListenerOptions>,
) -> Result<(PacketSocket, Connection), io::Error> {
    let init_settings: ConnInitSettings = options.socket.clone().into();
    let socket_id = init_settings.local_sockid;

    'outer: loop {
        let mut listen = Listen::new(init_settings.clone(), false);
        loop {
            let packet = socket.receive().await;
            debug!("{:?}:listen  - {:?}", socket_id, packet);

            let result = listen.handle_packet(Instant::now(), packet);
            debug!("{:?}:listen  - {:?}", socket_id, result);

            use ConnectionResult::*;
            match result {
                SendPacket(packet) => {
                    let _ = socket.send(packet).await?;
                }
                NotHandled(e) => {
                    warn!("{:?}", e);
                }
                Reject(packet, rej) => {
                    warn!("Remote was rejected: {rej}, trying again");
                    if let Some(packet) = packet {
                        let _ = socket.send(packet).await?;
                    }
                    continue 'outer;
                }
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
}
