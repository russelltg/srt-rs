use bytes::BytesMut;
use futures::select;
use log::{debug, warn};

use std::{
    io::{self, Cursor, ErrorKind},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use srt_protocol::{
    accesscontrol::AllowAllStreamAcceptor,
    pending_connection::{
        connect::Connect, listen::Listen, rendezvous::Rendezvous, ConnInitSettings,
        ConnectionResult,
    },
    Connection, Packet, SeqNumber,
};

use futures::prelude::*;
use tokio::{net::UdpSocket, time::interval};

pub async fn connect(
    sock: &UdpSocket,
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

    let mut ser_buffer = Vec::new();

    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => connect.handle_packet(packet?, Instant::now()),
        };

        debug!("{:?}:connect - {:?}", streamid, result);
        match result {
            ConnectionResult::SendPacket((packet, sa)) => {
                ser_buffer.clear();
                packet.serialize(&mut ser_buffer);
                sock.send_to(&ser_buffer, sa).await?;
            }
            ConnectionResult::NotHandled(e) => {
                warn!("{:?}", e);
            }
            ConnectionResult::Reject(rp, rr) => {
                if let Some((packet, sa)) = rp {
                    ser_buffer.clear();
                    packet.serialize(&mut ser_buffer);
                    sock.send_to(&ser_buffer, sa).await?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    Box::new(rr),
                ));
            }
            ConnectionResult::Connected(pa, conn) => {
                if let Some((packet, sa)) = pa {
                    ser_buffer.clear();
                    packet.serialize(&mut ser_buffer);
                    sock.send_to(&ser_buffer, sa).await?;
                }
                return Ok(conn);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn listen(
    sock: &UdpSocket,
    init_settings: ConnInitSettings,
) -> Result<Connection, io::Error> {
    let streamid = init_settings.local_sockid;
    let mut a = AllowAllStreamAcceptor::default();
    let mut listen = Listen::new(init_settings);
    let mut ser_buffer = Vec::new();
    loop {
        let packet = get_packet(sock).await?;
        debug!("{:?}:listen  - {:?}", streamid, packet);

        let result = listen.handle_packet(packet, Instant::now(), &mut a);
        debug!("{:?}:listen  - {:?}", streamid, result);

        match result {
            ConnectionResult::SendPacket((packet, sa)) => {
                ser_buffer.clear();
                packet.serialize(&mut ser_buffer);
                sock.send_to(&ser_buffer, sa).await?;
            }
            ConnectionResult::NotHandled(e) => {
                warn!("{:?}", e);
            }
            ConnectionResult::Reject(_, _) => todo!(),
            ConnectionResult::Connected(pa, c) => {
                if let Some((packet, sa)) = pa {
                    ser_buffer.clear();
                    packet.serialize(&mut ser_buffer);
                    sock.send_to(&ser_buffer, sa).await?;
                }
                return Ok(c);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn rendezvous(
    sock: &UdpSocket,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    init_settings: ConnInitSettings,
    starting_seqno: SeqNumber,
) -> Result<Connection, io::Error> {
    let sockid = init_settings.local_sockid;
    let mut rendezvous = Rendezvous::new(local_addr, remote_public, init_settings, starting_seqno);

    let mut tick_interval = interval(Duration::from_millis(100));
    let mut ser_buffer = Vec::new();

    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => rendezvous.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => rendezvous.handle_packet(packet?, Instant::now()),
        };

        debug!("{:?}:rendezvous - {:?}", sockid, result);
        match result {
            ConnectionResult::SendPacket((packet, sa)) => {
                ser_buffer.clear();
                packet.serialize(&mut ser_buffer);
                sock.send_to(&ser_buffer, sa).await?;
            }
            ConnectionResult::NotHandled(e) => {
                warn!("rendezvous {:?} error: {}", sockid, e);
            }
            ConnectionResult::Reject(_, _) => todo!(),
            ConnectionResult::Connected(pa, c) => {
                if let Some((packet, sa)) = pa {
                    ser_buffer.clear();
                    packet.serialize(&mut ser_buffer);
                    sock.send_to(&ser_buffer, sa).await?;
                }
                return Ok(c);
            }
            ConnectionResult::NoAction => {}
        }
    }
}

pub async fn get_packet(sock: &UdpSocket) -> Result<(Packet, SocketAddr), io::Error> {
    let mut deser_buffer = BytesMut::with_capacity(1024 * 1024);
    loop {
        sock.readable().await?;
        deser_buffer.clear();

        match sock.try_recv_buf_from(&mut deser_buffer) {
            Ok((size, t)) => match Packet::parse(
                &mut Cursor::new(&deser_buffer[0..size]),
                sock.local_addr()?.is_ipv6(),
            ) {
                Ok(pack) => return Ok((pack, t)),
                Err(e) => warn!("Failed to parse packet {}", e),
            },
            Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}
