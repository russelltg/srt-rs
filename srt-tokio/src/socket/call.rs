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
    protocol::pending_connection::{connect::Connect, ConnectionResult},
};

use crate::net::PacketSocket;

pub async fn bind_with(
    mut socket: PacketSocket,
    options: Valid<CallerOptions>,
) -> Result<(PacketSocket, Connection), io::Error> {
    let stream_id = options.stream_id.as_ref().map(|s| s.to_string());

    let mut tick_interval = interval(Duration::from_millis(100));
    let mut connect = Connect::new(
        options.remote,
        options.socket.connect.local.ip(),
        options.socket.clone().into(),
        stream_id.clone(),
        rand::random(),
    );
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = socket.receive().fuse() => connect.handle_packet(packet, Instant::now()),
        };

        debug!("{:?}:connect - {:?}", stream_id, result);
        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                let _ = socket.send(packet).await?;
            }
            NotHandled(e) => {
                warn!("{:?}", e);
            }
            Reject(rp, rr) => {
                if let Some(packet) = rp {
                    let _ = socket.send(packet).await?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    Box::new(rr),
                ));
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
