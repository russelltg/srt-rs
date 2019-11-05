use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use failure::{bail, Error};

use futures::prelude::*;

use log::{info, warn};
use tokio::timer::Interval;

use crate::packet::{
    ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo, Packet, ShakeType,
    SocketType, SrtControlPacket, SrtHandshake, SrtShakeFlags,
};
use crate::util::{get_packet, select_discard, Selected};
use crate::{ConnectionSettings, SocketID, SrtVersion};

pub async fn connect<T>(
    sock: &mut T,
    remote: SocketAddr,
    local_sockid: SocketID,
    local_addr: IpAddr,
    tsbpd_latency: Duration,
    _crypto: Option<(u8, String)>,
) -> Result<ConnectionSettings, Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    let mut send_interval = Interval::new(Instant::now(), Duration::from_millis(100));

    let request_packet = Packet::Control(ControlPacket {
        dest_sockid: SocketID(0),
        timestamp: 0, // TODO: this is not zero in the reference implementation
        control_type: ControlTypes::Handshake(HandshakeControlInfo {
            init_seq_num: rand::random(),
            max_packet_size: 1500, // TODO: take as a parameter
            max_flow_size: 8192,   // TODO: take as a parameter
            socket_id: local_sockid,
            shake_type: ShakeType::Induction,
            peer_addr: local_addr,
            syn_cookie: 0,
            info: HandshakeVSInfo::V4(SocketType::Datagram),
        }),
    });

    sock.send((request_packet.clone(), remote)).await?;

    // get first response packet
    let (timestamp, hs_info) = loop {
        // just drop the future that didn't finish first
        match select_discard(send_interval.next(), get_packet(sock)).await {
            Selected::Left(_interval_reached) => {
                sock.send((request_packet.clone(), remote)).await?
            }
            Selected::Right(Ok((packet, addr))) => {
                // make sure the socket id and packet type match
                if let Packet::Control(ControlPacket {
                    timestamp,
                    control_type:
                        ControlTypes::Handshake(
                            info @ HandshakeControlInfo {
                                shake_type: ShakeType::Induction,
                                ..
                            },
                        ),
                    ..
                }) = packet
                {
                    if addr != remote {
                        warn!("Expected packet from {}, got {}", remote, addr);
                        continue;
                    }
                    if info.info.version() != 5 {
                        warn!("Handshake was HSv4, expected HSv5");
                        continue;
                    }
                    break (timestamp, info);
                }
            }
            Selected::Right(Err(e)) => bail!(e),
        }
    };

    info!("Got hanshake from {}", remote);

    // send back a packet with the same syn cookie
    let pack = Packet::Control(ControlPacket {
        dest_sockid: SocketID(0),
        timestamp,
        control_type: ControlTypes::Handshake(HandshakeControlInfo {
            shake_type: ShakeType::Conclusion,
            socket_id: local_sockid,
            info: HandshakeVSInfo::V5 {
                crypto_size: 0, // TODO: implement
                ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                    version: SrtVersion::CURRENT,
                    // TODO: this is hyper bad, don't blindly set send flag
                    // if you don't pass TSBPDRCV, it doens't set the latency correctly for some reason. Requires more research
                    peer_latency: Duration::from_secs(0), // TODO: research
                    flags: SrtShakeFlags::TSBPDSND | SrtShakeFlags::TSBPDRCV, // TODO: the reference implementation sets a lot more of these, research
                    latency: tsbpd_latency,
                })),
                ext_km: None,
                // ext_km: self.crypto.as_mut().map(|manager| {
                //     SrtControlPacket::KeyManagerRequest(SrtKeyMessage {
                //         pt: 2,       // TODO: what is this
                //         sign: 8_233, // TODO: again
                //         keki: 0,
                //         cipher: CipherType::CTR,
                //         auth: 0,
                //         se: 2,
                //         salt: Vec::from(manager.salt()),
                //         even_key: Some(manager.wrap_key().unwrap()),
                //         odd_key: None,
                //         wrap_data: [0; 8],
                //     })
                // }),
                ext_config: None,
            },
            ..hs_info
        }),
    });

    sock.send((pack.clone(), remote)).await?;

    loop {
        match select_discard(send_interval.next(), get_packet(sock)).await {
            Selected::Left(_interval_reached) => sock.send((pack.clone(), remote)).await?,
            Selected::Right(Ok((packet, from))) => {
                if let Packet::Control(ControlPacket {
                    dest_sockid,
                    control_type:
                        ControlTypes::Handshake(
                            info @ HandshakeControlInfo {
                                shake_type: ShakeType::Conclusion,
                                ..
                            },
                        ),
                    ..
                }) = packet
                {
                    if from != remote {
                        warn!("Got packet from {}, expected {}", from, remote)
                    }
                    if dest_sockid != local_sockid {
                        warn!(
                            "Unexpected destination socket id, expected {:?}, got {:?}",
                            local_sockid, dest_sockid
                        );
                        continue;
                    }
                    let latency = if let HandshakeVSInfo::V5 {
                        ext_hs: Some(SrtControlPacket::HandshakeResponse(hs)),
                        ..
                    } = info.info
                    {
                        hs.latency
                    } else {
                        warn!("Did not get SRT handhsake in conclusion handshake packet, using latency from connector's end");
                        tsbpd_latency
                    };

                    info!(
                        "Got second handshake, connection established to {} with latency {:?}",
                        remote, latency
                    );
                    return Ok(ConnectionSettings {
                        remote,
                        max_flow_size: info.max_flow_size,
                        max_packet_size: info.max_packet_size,
                        init_seq_num: info.init_seq_num,
                        socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
                        local_sockid,
                        remote_sockid: info.socket_id,
                        tsbpd_latency: latency,
                        // TODO: is this right? Needs testing.
                        handshake_returner: Box::new(move |_| None),
                    });
                }
            }
            Selected::Right(Err(e)) => bail!(e),
        }
    }
}
