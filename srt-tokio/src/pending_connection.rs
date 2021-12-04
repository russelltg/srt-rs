use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use futures::prelude::*;
use futures::select;
use log::{debug, warn};
use tokio::time::interval;

use srt_protocol::{
    connection::Connection,
    packet::*,
    protocol::pending_connection::{
        connect::Connect, listen::Listen, rendezvous::Rendezvous, ConnectionResult,
    },
    settings::*,
};

use crate::net::PacketSocket;

pub async fn connect(
    socket: &mut PacketSocket,
    remote: SocketAddr,
    local_addr: IpAddr,
    init_settings: ConnInitSettings,
    streamid: Option<String>,
    starting_seqno: SeqNumber,
) -> Result<Connection, io::Error> {
    let mut connect = Connect::new(
        remote,
        local_addr,
        init_settings,
        streamid.clone(),
        starting_seqno,
    );
    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = socket.receive().fuse() => connect.handle_packet(packet, Instant::now()),
        };

        debug!("{:?}:connect - {:?}", streamid, result);
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
            Connected(pa, conn) => {
                if let Some(packet) = pa {
                    let _ = socket.send(packet).await?;
                }
                return Ok(conn);
            }
            NoAction => {}
            RequestAccess(_) => {}
            Failure(error) => return Err(error),
        }
    }
}

pub async fn listen(
    sockt: &mut PacketSocket,
    init_settings: ConnInitSettings,
) -> Result<Connection, io::Error> {
    let streamid = init_settings.local_sockid;
    let mut listen = Listen::new(init_settings, false);
    loop {
        let packet = sockt.receive().await;
        debug!("{:?}:listen  - {:?}", streamid, packet);

        let result = listen.handle_packet(Instant::now(), packet);
        debug!("{:?}:listen  - {:?}", streamid, result);

        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                sockt.send(packet).await?;
            }
            NotHandled(e) => {
                warn!("{:?}", e);
            }
            Reject(_, _) => todo!(),
            Connected(pa, c) => {
                if let Some(packet) = pa {
                    sockt.send(packet).await?;
                }
                return Ok(c);
            }
            NoAction => {}
            RequestAccess(_) => {}
            Failure(error) => return Err(error),
        }
    }
}

pub async fn rendezvous(
    socket: &mut PacketSocket,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    init_settings: ConnInitSettings,
    starting_seqno: SeqNumber,
) -> Result<Connection, io::Error> {
    let sockid = init_settings.local_sockid;
    let mut rendezvous = Rendezvous::new(local_addr, remote_public, init_settings, starting_seqno);
    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => rendezvous.handle_tick(now.into()),
            packet = socket.receive().fuse() => rendezvous.handle_packet(packet, Instant::now()),
        };

        debug!("{:?}:rendezvous - {:?}", sockid, result);
        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                socket.send(packet).await?;
            }
            NotHandled(e) => {
                warn!("rendezvous {:?} error: {}", sockid, e);
            }
            Reject(_, _) => todo!(),
            Connected(pa, c) => {
                if let Some(packet) = pa {
                    socket.send(packet).await?;
                }
                return Ok(c);
            }
            NoAction => {}
            RequestAccess(_) => {}
            Failure(error) => return Err(error),
        }
    }
}
