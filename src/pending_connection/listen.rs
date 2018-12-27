use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use failure::{bail, Error};
use futures::prelude::*;
use log::{info, warn};

use crate::connected::Connected;
use crate::packet::{
    ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo, Packet, ShakeType,
    SrtControlPacket,
};
use crate::{ConnectionSettings, SocketID};

pub struct Listen<T> {
    state: ConnectionState,
    sock: Option<T>,
    local_socket_id: SocketID,
    tsbpd_latency: Duration,
}

impl<T> Listen<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(sock: T, local_socket_id: SocketID, tsbpd_latency: Duration) -> Listen<T> {
        info!("Listening...");

        Listen {
            sock: Some(sock),
            state: ConnectionState::WaitingForHandshake,
            local_socket_id,
            tsbpd_latency,
        }
    }
}

// The state of the connection initiation
enum ConnectionState {
    WaitingForHandshake,
    WaitingForCookieResp(i32 /*cookie*/),
}

impl<T> Future for Listen<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        loop {
            let sock = self
                .sock
                .as_mut()
                .expect("Poll after PendingConnection completion");
            sock.poll_complete()?;

            let (packet, addr) = match sock.poll() {
                Ok(Async::Ready(Some(p))) => p,
                Ok(Async::Ready(None)) => {
                    bail!("Unexpected EOF when reading stream");
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    warn!("Error decoding packet: {:?}", e);

                    continue;
                }
            };

            match self.state {
                // Haven't received anything yet, waiting for the first handshake
                ConnectionState::WaitingForHandshake => {
                    // see if it's a handshake request
                    if let Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(shake),
                        timestamp,
                        ..
                    }) = packet
                    {
                        info!("Handshake recieved from {:?}", addr);

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
                                socket_id: self.local_socket_id,
                                info: HandshakeVSInfo::V5 {
                                    crypto_size: 0,
                                    ext_hs: None,
                                    ext_km: None,
                                    ext_config: None,
                                },
                                ..shake
                            }),
                        });

                        self.state = ConnectionState::WaitingForCookieResp(cookie);

                        // send the packet
                        sock.start_send((resp_handshake, addr))?;
                    }
                }

                // Received the first packet and waiting for the same cookie to come back
                ConnectionState::WaitingForCookieResp(cookie) => {
                    // https://tools.ietf.org/html/draft-gg-udt-03#page-10
                    // The server, when receiving a handshake packet and the correct cookie,
                    // compares the packet size and maximum window size with its own values
                    // and set its own values as the smaller ones. The result values are
                    // also sent back to the client by a response handshake packet, together
                    // with the server's version and initial sequence number. The server is
                    // ready for sending/receiving data right after this step is finished.
                    // However, it must send back response packet as long as it receives any
                    // further handshakes from the same client.

                    info!("Second handshake recieved from {:?}", addr);

                    if let Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(shake),
                        timestamp,
                        ..
                    }) = packet
                    {
                        if shake.shake_type != ShakeType::Conclusion {
                            // discard
                            continue;
                        }

                        // check that the cookie matches
                        if shake.syn_cookie != cookie {
                            // wait for the next one
                            warn!(
                                "Received invalid cookie handshake from {:?}: {}, should be {}",
                                addr, shake.syn_cookie, cookie
                            );
                            continue;
                        }

                        if shake.info.version() != 5 {
                            bail!("Conclusion was HSv4, not HSv5, terminating connection");
                        }

                        info!("Cookie was correct, connection established to {:?}", addr);

                        // select the smaller packet size and max window size
                        // TODO: allow configuration of these parameters, for now just
                        // use the remote ones

                        // construct a packet to send back
                        let resp_handshake = Packet::Control(ControlPacket {
                            timestamp,
                            dest_sockid: shake.socket_id,
                            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                                syn_cookie: cookie,
                                socket_id: self.local_socket_id,
                                ..shake
                            }),
                        });

                        // send the packet
                        sock.start_send((resp_handshake, addr))?;
                        // poll_completed here beacuse we won't get a chance to call it later
                        sock.poll_complete()?;

                        let latency = if let HandshakeVSInfo::V5 {
                            ext_hs: Some(SrtControlPacket::HandshakeResponse(hs)),
                            ..
                        } = shake.info
                        {
                            Duration::max(hs.latency, self.tsbpd_latency)
                        } else {
                            warn!("Did not get SRT handshake response in final handshake packet, using latency from this end");
                            self.tsbpd_latency
                        };

                        // finish the connection
                        return Ok(Async::Ready(Connected::new(
                            self.sock.take().unwrap(),
                            ConnectionSettings {
                                init_seq_num: shake.init_seq_num,
                                remote_sockid: shake.socket_id,
                                remote: addr,
                                max_flow_size: 16000, // TODO: what is this?
                                max_packet_size: shake.max_packet_size,
                                local_sockid: self.local_socket_id,
                                socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
                                tsbpd_latency: latency,
                            },
                        )));
                    }
                }
            }
        }
    }
}
