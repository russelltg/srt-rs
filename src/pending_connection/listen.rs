use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use failure::{bail, Error};
use futures::prelude::*;
use log::{debug, info, warn};

use crate::packet::{
    ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo, Packet, ShakeType,
    SrtControlPacket, SrtHandshake,
};
use crate::util::get_packet;
use crate::{Connection, ConnectionSettings, SocketID};

pub async fn listen<T>(
    sock: &mut T,
    local_sockid: SocketID,
    tsbpd_latency: Duration,
) -> Result<Connection, Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    info!("Listening...");

    // keep on retrying
    let (cookie, from, induction_pkt) = get_handshake(sock, local_sockid).await?;

    info!("Got induction shake from {}", from);

    let (latency, shake, resp_handshake) = get_conclusion(
        sock,
        &induction_pkt,
        cookie,
        local_sockid,
        tsbpd_latency,
        &from,
    )
    .await?;
    // select the smaller packet size and max window size
    // TODO: allow configuration of these parameters, for now just
    // use the remote ones

    // finish the connection
    Ok(Connection {
        settings: ConnectionSettings {
            init_seq_num: shake.init_seq_num,
            remote_sockid: shake.socket_id,
            remote: from,
            max_flow_size: 16000, // TODO: what is this?
            max_packet_size: shake.max_packet_size,
            local_sockid,
            socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
            tsbpd_latency: latency,
        },
        hs_returner: Box::new(move |_| Some(resp_handshake.clone())),
    })
}

async fn get_handshake<
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
>(
    sock: &mut T,
    local_sockid: SocketID,
) -> Result<(i32, SocketAddr, Packet), Error> {
    loop {
        let (packet, from) = get_packet(sock).await?;

        if let Packet::Control(ControlPacket {
            control_type: ControlTypes::Handshake(shake),
            timestamp,
            ..
        }) = packet
        {
            if shake.shake_type != ShakeType::Induction {
                info!(
                    "Expected Induction (1), got {:?} ({})",
                    shake.shake_type, shake.shake_type as u32
                );
                continue;
            }

            // https://tools.ietf.org/html/draft-gg-udt-03#page-9
            // When the server first receives the connection request from a client,
            // it generates a cookie value according to the client address and a
            // secret key and sends it back to the client. The client must then send
            // back the same cookie to the server.

            // generate the cookie, which is just a hash of the address
            // TODO: the reference impl uses the time, maybe we should here
            let cookie = {
                let mut hasher = DefaultHasher::new();
                shake.peer_addr.hash(&mut hasher);
                hasher.finish() as i32 // this will truncate, which is fine
            };

            // we expect HSv5, so upgrade it

            // construct a packet to send back
            let resp_handshake = Packet::Control(ControlPacket {
                timestamp,
                dest_sockid: shake.socket_id,
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    syn_cookie: cookie,
                    socket_id: local_sockid,
                    info: HandshakeVSInfo::V5 {
                        crypto_size: 0,
                        ext_hs: None,
                        ext_km: None,
                        ext_config: None,
                    },
                    ..shake
                }),
            });

            sock.send((resp_handshake.clone(), from)).await?;
            debug!("Sending induction to {}", from);

            return Ok((cookie, from, resp_handshake));
        } else {
            continue; // try again
        };
    }
}

async fn get_conclusion<
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
>(
    sock: &mut T,
    induction_hs: &Packet,
    cookie: i32,
    local_socket_id: SocketID,
    tsbpd_latency: Duration,
    from: &SocketAddr,
) -> Result<(Duration, HandshakeControlInfo, Packet), Error> {
    // https://tools.ietf.org/html/draft-gg-udt-03#page-10
    // The server, when receiving a handshake packet and the correct cookie,
    // compares the packet size and maximum window size with its own values
    // and set its own values as the smaller ones. The result values are
    // also sent back to the client by a response handshake packet, together
    // with the server's version and initial sequence number. The server is
    // ready for sending/receiving data right after this step is finished.
    // However, it must send back response packet as long as it receives any
    // further handshakes from the same client.

    // first packet received, wait for response (with cookie)
    loop {
        match get_packet(sock).await? {
            (
                Packet::Control(ControlPacket {
                    control_type: ControlTypes::Handshake(ref shake),
                    timestamp,
                    ..
                }),
                from_second,
            ) if from_second == *from => {
                if shake.shake_type == ShakeType::Induction {
                    // it maybe missed our induction packet, so send it again
                    sock.send((induction_hs.clone(), *from)).await?;
                    continue;
                } else if shake.shake_type != ShakeType::Conclusion {
                    // discard
                    info!(
                        "Expected Conclusion (-1) packet, got {:?} ({}). Discarding handshake.",
                        shake.shake_type, shake.shake_type as i32
                    );
                    continue;
                }

                // check that the cookie matches
                if shake.syn_cookie != cookie {
                    // wait for the next one
                    warn!(
                        "Received invalid cookie handshake from {:?}: {}, should be {}",
                        from, shake.syn_cookie, cookie
                    );
                    continue;
                }

                if shake.info.version() != 5 {
                    bail!("Conclusion was HSv4, not HSv5, terminating connection");
                }

                info!("Cookie was correct, connection established to {:?}", from);

                let (srt_handshake, crypto_size) = if let HandshakeVSInfo::V5 {
                    ext_hs: Some(SrtControlPacket::HandshakeRequest(hs)),
                    crypto_size,
                    ..
                } = shake.info
                {
                    (hs, crypto_size)
                } else {
                    bail!("Did not get SRT handshake request in conclusion handshake packet, using latency from this end");
                };

                let latency = Duration::max(srt_handshake.latency, tsbpd_latency);

                // construct a packet to send back
                let resp_handshake = Packet::Control(ControlPacket {
                    timestamp,
                    dest_sockid: shake.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        syn_cookie: cookie,
                        socket_id: local_socket_id,
                        info: HandshakeVSInfo::V5 {
                            ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                                latency,
                                ..srt_handshake
                            })),
                            ext_km: None,
                            ext_config: None,
                            crypto_size,
                        },
                        ..*shake
                    }),
                });

                // send the packet
                sock.send((resp_handshake.clone(), *from)).await?;

                return Ok((latency, shake.clone(), resp_handshake));
            }
            _ => continue,
        }
    }
}
