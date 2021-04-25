use futures::select;
use log::{debug, warn};

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{
        connect::Connect, listen::Listen, rendezvous::Rendezvous, ConnInitSettings,
        ConnectionResult,
    },
    Connection, Packet, PacketParseError,
};

use futures::prelude::*;
use tokio::time::interval;

pub async fn connect<T>(
    sock: &mut T,
    remote: SocketAddr,
    local_addr: IpAddr,
    init_settings: ConnInitSettings,
    streamid: Option<String>,
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Unpin,
{
    let mut connect = Connect::new(remote, local_addr, init_settings, streamid);

    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => connect.handle_packet(packet?),
        };
        debug!("sending packet");

        match result {
            ConnectionResult::SendPacket(packet) => {
                sock.send(packet).await?;
            }
            ConnectionResult::NotHandled(e) => {
                warn!("{:?}", e);
            }
            ConnectionResult::Reject(rp, rr) => {
                if let Some(rp) = rp {
                    sock.send(rp).await?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    Box::new(rr),
                ));
            }
            ConnectionResult::Connected(pa, conn) => {
                if let Some(pa) = pa {
                    sock.send(pa).await?;
                }
                return Ok(conn);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn listen<T>(
    sock: &mut T,
    init_settings: ConnInitSettings,
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Unpin,
{
    let mut a = AllowAllStreamAcceptor::default();
    let mut listen = Listen::new(init_settings);

    loop {
        let packet = get_packet(sock).await?;
        debug!("got packet {:?}", packet);
        match listen.handle_packet(packet, Instant::now(), &mut a) {
            ConnectionResult::SendPacket(packet) => sock.send(packet).await?,
            ConnectionResult::NotHandled(e) => {
                warn!("{:?}", e);
            }
            ConnectionResult::Reject(_, _) => todo!(),
            ConnectionResult::Connected(pa, c) => {
                if let Some(pa) = pa {
                    sock.send(pa).await?;
                }
                return Ok(c);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn rendezvous<T>(
    sock: &mut T,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    init_settings: ConnInitSettings,
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Unpin,
{
    let sockid = init_settings.local_sockid;
    let mut rendezvous = Rendezvous::new(local_addr, remote_public, init_settings);

    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => rendezvous.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => rendezvous.handle_packet(packet?, Instant::now()),
        };

        // trace!("Ticking {:?} {:?}", sockid, rendezvous);

        match result {
            ConnectionResult::SendPacket(packet) => {
                sock.send(packet).await?;
            }
            ConnectionResult::NotHandled(e) => {
                warn!("rendezvous {:?} error: {}", sockid, e);
            }
            ConnectionResult::Reject(_, _) => todo!(),
            ConnectionResult::Connected(pa, c) => {
                if let Some(pa) = pa {
                    sock.send(pa).await?;
                }
                return Ok(c);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn get_packet<
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>> + Unpin,
>(
    sock: &mut T,
) -> Result<(Packet, SocketAddr), io::Error> {
    loop {
        match sock.next().await {
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "")),
            Some(Ok(t)) => break Ok(t),
            Some(Err(e)) => warn!("Failed to parse packet: {}", e),
        }
    }
}
