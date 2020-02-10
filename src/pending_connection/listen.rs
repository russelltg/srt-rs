use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use failure::Error;
use futures::prelude::*;
use log::warn;

use crate::packet::*;
use crate::protocol::handshake::Handshake;
use crate::util::get_packet;
use crate::{Connection, ConnectionSettings, SocketID};

use ListenError::*;
use ListenState::*;

pub struct Listen {
    config: ListenConfiguration,
    state: ListenState,
}

pub struct ListenConfiguration {
    pub local_socket_id: SocketID,
    pub tsbpd_latency: Duration,
}

#[derive(Clone)]
pub struct ConclusionWaitState {
    timestamp: i32,
    from: (SocketAddr, SocketID),
    cookie: i32,
    induction_response: Packet,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ListenState {
    InductionWait,
    ConclusionWait(ConclusionWaitState),
    Connected(ControlPacket, ConnectionSettings),
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ListenError {
    //#[error("Expected Control packet, expected: {0} found: {1}")]
    ControlExpected(ShakeType, DataPacket),
    //#[error("Expected Handshake packet, expected: {0} found: {1}")]
    HandshakeExpected(ShakeType, ControlTypes),
    //#[error("Expected Induction (1) packet, found: {0}")]
    InductionExpected(HandshakeControlInfo),
    //#[error("Expected Conclusion (-1) packet, found: {0}")]
    ConclusionExpected(HandshakeControlInfo),
    //#[error("Unsupported protocol version, expected: v5 found v{0}")]
    UnsupportedProtocolVersion(u32),
    //#[error("Received invalid cookie handshake from [address], expected: {0} found {1}")]
    InvalidHandshakeCookie(i32, i32),
    //#[error("Expected SRT handshake request in conclusion handshake, found {0}")]
    SrtHandshakeExpected(HandshakeControlInfo),
}

type ListenResult = Result<Option<(Packet, SocketAddr)>, ListenError>;

impl Listen {
    pub fn new(config: ListenConfiguration) -> Listen {
        Listen {
            config,
            state: InductionWait,
        }
    }
    fn wait_for_induction(
        &mut self,
        from: SocketAddr,
        timestamp: i32,
        shake: HandshakeControlInfo,
    ) -> ListenResult {
        match shake.shake_type {
            ShakeType::Induction => {
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
                let induction_response = Packet::Control(ControlPacket {
                    timestamp,
                    dest_sockid: shake.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        syn_cookie: cookie,
                        socket_id: self.config.local_socket_id,
                        info: HandshakeVSInfo::V5 {
                            crypto_size: 0,
                            ext_hs: None,
                            ext_km: None,
                            ext_config: None,
                        },
                        ..shake
                    }),
                });

                // save induction message for potential later retransmit
                let save_induction_response = induction_response.clone();
                self.state = ConclusionWait(ConclusionWaitState {
                    timestamp,
                    from: (from, shake.socket_id),
                    cookie,
                    induction_response: save_induction_response,
                });
                Ok(Some((induction_response, from)))
            }
            _ => Err(InductionExpected(shake)),
        }
    }

    fn wait_for_conclusion(
        &mut self,
        from: SocketAddr,
        timestamp: i32,
        state: ConclusionWaitState,
        shake: HandshakeControlInfo,
    ) -> ListenResult {
        // https://tools.ietf.org/html/draft-gg-udt-03#page-10
        // The server, when receiving a handshake packet and the correct cookie,
        // compares the packet size and maximum window size with its own values
        // and set its own values as the smaller ones. The result values are
        // also sent back to the client by a response handshake packet, together
        // with the server's version and initial sequence number. The server is
        // ready for sending/receiving data right after this step is finished.
        // However, it must send back response packet as long as it receives any
        // further handshakes from the same client.

        const VERSION_5: u32 = 5;

        match (shake.shake_type, shake.info.version(), shake.syn_cookie) {
            (ShakeType::Induction, _, _) => Ok(Some((state.induction_response, from))),
            // first induction received, wait for response (with cookie)
            (ShakeType::Conclusion, VERSION_5, syn_cookie) if syn_cookie == state.cookie => {
                let (srt_handshake, crypto_size) = match &shake.info {
                    HandshakeVSInfo::V5 {
                        ext_hs: Some(SrtControlPacket::HandshakeRequest(hs)),
                        crypto_size,
                        ..
                    } => Ok((hs, *crypto_size)),
                    _ => Err(SrtHandshakeExpected(shake.clone())),
                }?;

                let latency = Duration::max(srt_handshake.latency, self.config.tsbpd_latency);

                // construct a packet to send back
                let resp_handshake = ControlPacket {
                    timestamp,
                    dest_sockid: shake.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        syn_cookie: state.cookie,
                        socket_id: self.config.local_socket_id,
                        info: HandshakeVSInfo::V5 {
                            ext_hs: Some(SrtControlPacket::HandshakeResponse(SrtHandshake {
                                latency,
                                ..*srt_handshake
                            })),
                            ext_km: None,
                            ext_config: None,
                            crypto_size,
                        },
                        ..shake
                    }),
                };

                // select the smaller packet size and max window size
                // TODO: allow configuration of these parameters, for now just
                // use the remote ones

                // finish the connection
                let settings = ConnectionSettings {
                    init_seq_num: shake.init_seq_num,
                    remote_sockid: shake.socket_id,
                    remote: from,
                    max_flow_size: 16000, // TODO: what is this?
                    max_packet_size: shake.max_packet_size,
                    local_sockid: self.config.local_socket_id,
                    socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
                    tsbpd_latency: latency,
                };

                self.state = Connected(resp_handshake.clone(), settings);

                Ok(Some((Packet::Control(resp_handshake), from)))
            }
            (ShakeType::Conclusion, VERSION_5, syn_cookie) => {
                Err(InvalidHandshakeCookie(state.cookie, syn_cookie))
            }
            (ShakeType::Conclusion, version, _) => Err(UnsupportedProtocolVersion(version)),
            (_, _, _) => Err(ConclusionExpected(shake)),
        }
    }

    pub fn handle_control_packets(
        &mut self,
        control: ControlPacket,
        from: SocketAddr,
    ) -> ListenResult {
        match (self.state.clone(), control.control_type) {
            (InductionWait, ControlTypes::Handshake(shake)) => {
                self.wait_for_induction(from, control.timestamp, shake)
            }
            (InductionWait, control_type) => {
                Err(HandshakeExpected(ShakeType::Induction, control_type))
            }
            (ConclusionWait(state), ControlTypes::Handshake(shake)) => {
                self.wait_for_conclusion(from, control.timestamp, state, shake)
            }
            (ConclusionWait(_), control_type) => {
                Err(HandshakeExpected(ShakeType::Conclusion, control_type))
            }
            (Connected(_, _), _) => Ok(None),
        }
    }

    pub fn handle_packet(&mut self, (packet, from): (Packet, SocketAddr)) -> ListenResult {
        match packet {
            Packet::Control(control) => self.handle_control_packets(control, from),
            Packet::Data(data) => Err(ControlExpected(ShakeType::Induction, data)),
        }
    }

    pub fn state(&self) -> &ListenState {
        &self.state
    }
}

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
    let mut listen = Listen {
        config: ListenConfiguration {
            local_socket_id: local_sockid,
            tsbpd_latency,
        },
        state: InductionWait,
    };

    loop {
        let packet = get_packet(sock).await?;
        match listen.handle_packet(packet) {
            Ok(Some(packet)) => {
                sock.send(packet).await?;
            }
            Err(e) => {
                warn!("{:?}", e);
            }
            _ => {}
        }
        if let Connected(resp_handshake, settings) = listen.state.clone() {
            return Ok(Connection {
                settings,
                handshake: Handshake::Listener(resp_handshake.control_type),
            });
        }
    }
}
