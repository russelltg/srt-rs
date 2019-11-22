use std::cmp;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use failure::{bail, Error};
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::warn;
use tokio::time::interval;

use crate::packet::{ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SocketType};
use crate::util::{select_discard, Selected};
use crate::{ConnectionSettings, ControlPacket, Packet, SeqNumber, SocketID};

pub async fn rendezvous<T>(
    sock: &mut T,
    local_socket_id: SocketID,
    local_addr: IpAddr,
    remote_public: SocketAddr,
    tsbpd_latency: Duration,
) -> Result<ConnectionSettings, Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    let mut snd_interval = interval(Duration::from_millis(100));
    let mut init_seq_num = rand::random();

    let (info, packet) = loop {
        match select_discard(snd_interval.next(), sock.next()).await {
            Selected::Left(_) => {
                send_packet(
                    sock,
                    init_seq_num,
                    local_socket_id,
                    local_addr,
                    remote_public,
                )
                .await?
            }
            Selected::Right(Some(Ok((packet, from_addr)))) => {
                if from_addr != remote_public {
                    warn!(
                        "Received handshake packet from unrecognized location: {}",
                        from_addr
                    );
                    continue;
                }

                let info = match packet {
                    Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(info),
                        ..
                    }) => info,
                    _ => {
                        warn!("Received non-handshake packet when negotiating rendezvous");
                        continue;
                    }
                };

                // update our init seq num
                init_seq_num = cmp::max(info.init_seq_num, init_seq_num);

                match info.shake_type {
                    ShakeType::Waveahand => {
                        // we now respond with a Conclusion packet
                        let new_packet = Packet::Control(ControlPacket {
                            dest_sockid: info.socket_id,
                            timestamp: 0, // TODO: deal with timestamp
                            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                                shake_type: ShakeType::Conclusion,
                                socket_id: local_socket_id,
                                peer_addr: local_addr,
                                init_seq_num,
                                ..info
                            }),
                        });

                        sock.send((new_packet, remote_public)).await?;
                    }
                    ShakeType::Conclusion => {
                        // connection is created, send Agreement back
                        // TODO: if this packet gets dropped, this connection will never init. This is a pretty big bug.
                        let new_packet = Packet::Control(ControlPacket {
                            dest_sockid: info.socket_id,
                            timestamp: 0, // TODO: deal with timestamp,
                            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                                shake_type: ShakeType::Agreement,
                                socket_id: local_socket_id,
                                peer_addr: local_addr,
                                ..info.clone()
                            }),
                        });

                        sock.send((new_packet.clone(), remote_public)).await?;

                        break (info, Some(new_packet));
                    }
                    ShakeType::Agreement => {
                        // connection is established
                        break (info, None);
                    }
                    ShakeType::Induction => {
                        warn!("Received induction handshake while initiating a rendezvous connection. Maybe you tried to pair connect with rendezvous?");
                    }
                }
            }
            Selected::Right(Some(Err(e))) => bail!("Failed to decode packet: {:?}", e),
            Selected::Right(None) => bail!("Underlying stream ended"),
        }
    };
    Ok(ConnectionSettings {
        remote: remote_public,
        max_flow_size: info.max_flow_size,
        max_packet_size: info.max_packet_size,
        init_seq_num: info.init_seq_num,
        socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
        local_sockid: local_socket_id,
        remote_sockid: info.socket_id,
        tsbpd_latency, // TODO: needs to be send in the handshakes
        handshake_returner: Box::new(move |pack| {
            if let Packet::Control(ControlPacket {
                control_type: ControlTypes::Handshake(info),
                ..
            }) = pack
            {
                match info.shake_type {
                    ShakeType::Conclusion => packet.clone(),
                    _ => None,
                }
            } else {
                None
            }
        }),
    })
}

async fn send_packet<T>(
    sock: &mut T,
    init_seq_num: SeqNumber,
    local_socket_id: SocketID,
    local_addr: IpAddr,
    remote_public: SocketAddr,
) -> Result<(), Error>
where
    T: Sink<(Packet, SocketAddr), Error = Error> + Unpin,
{
    let pack = Packet::Control(ControlPacket {
        timestamp: 0, // TODO: is this right?
        dest_sockid: SocketID(0),
        control_type: ControlTypes::Handshake(HandshakeControlInfo {
            init_seq_num,
            max_packet_size: 1500, // TODO: take as a parameter
            max_flow_size: 8192,   // TODO: take as a parameter
            socket_id: local_socket_id,
            shake_type: ShakeType::Waveahand, // as per the spec, the first packet is waveahand
            peer_addr: local_addr,
            syn_cookie: 0,
            info: HandshakeVSInfo::V4(SocketType::Datagram),
        }),
    });
    sock.send((pack, remote_public)).await?;
    Ok(())
}
