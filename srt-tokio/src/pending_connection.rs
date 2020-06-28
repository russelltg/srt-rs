use futures::select;
use log::warn;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use srt_protocol::{
    pending_connection::{
        connect::{Connect, ConnectState},
        listen::{Listen, ListenState},
        rendezvous::Rendezvous,
        ConnInitSettings,
    },
    protocol::handshake::Handshake,
    Connection, Packet, PacketParseError,
};

use crate::util::get_packet;

use futures::prelude::*;
use tokio::time::interval;

pub async fn connect<T>(
    sock: &mut T,
    remote: SocketAddr,
    local_addr: IpAddr,
    init_settings: ConnInitSettings,
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Unpin,
{
    let mut connect = Connect::new(remote, local_addr, init_settings);

    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => connect.handle_packet(packet?),
        };

        match result {
            Ok(Some(packet)) => {
                sock.send(packet).await?;
            }
            Err(e) => {
                warn!("{:?}", e);
            }
            _ => {}
        }
        if let ConnectState::Connected(settings) = connect.state() {
            return Ok(Connection {
                settings: settings.clone(),
                handshake: Handshake::Connector,
            });
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
    let mut listen = Listen::new(init_settings);

    loop {
        let packet = get_packet(sock).await?;
        match listen.handle_packet(packet) {
            Ok(Some(packet)) => sock.send(packet).await?,
            Err(e) => {
                warn!("{:?}", e);
            }
            _ => {}
        }
        if let ListenState::Connected(resp_handshake, settings) = listen.state().clone() {
            return Ok(Connection {
                settings,
                handshake: Handshake::Listener(resp_handshake.control_type),
            });
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
            packet = get_packet(sock).fuse() => rendezvous.handle_packet(packet?),
        };

        // trace!("Ticking {:?} {:?}", sockid, rendezvous);

        match result {
            Ok(Some((packet, address))) => {
                sock.send((Packet::Control(packet), address)).await?;
            }
            Err(e) => {
                warn!("rendezvous {:?} error: {}", sockid, e);
            }
            _ => {}
        }

        if let Some(connection) = rendezvous.connection() {
            return Ok(connection.clone());
        }
    }
}
