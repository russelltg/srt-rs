use std::net::SocketAddr;
use std::{
    error::Error,
    fmt, io,
    time::{Duration, Instant},
};

use futures::prelude::*;
use log::warn;

use crate::packet::*;
use crate::protocol::{handshake::Handshake, TimeStamp};
use crate::util::get_packet;
use crate::{Connection, ConnectionSettings, SocketID};

use super::cookie::gen_cookie;
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
    timestamp: TimeStamp,
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

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ListenError {
    ControlExpected(ShakeType, DataPacket),
    HandshakeExpected(ShakeType, ControlTypes),
    InductionExpected(HandshakeControlInfo),
    ConclusionExpected(HandshakeControlInfo),
    UnsupportedProtocolVersion(u32),
    InvalidHandshakeCookie(i32, i32),
    SrtHandshakeExpected(HandshakeControlInfo),
}

impl fmt::Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ControlExpected(shake, pack) => write!(
                f,
                "Expected Control packet, expected {:?}, found {:?}",
                shake, pack
            ),
            HandshakeExpected(expected, got) => write!(
                f,
                "Expected Handshake packet, expected: {:?} found: {:?}",
                expected, got
            ),
            InductionExpected(got) => write!(f, "Expected Induction (1) packet, found: {:?}", got),
            ConclusionExpected(got) => {
                write!(f, "Expected Conclusion (-1) packet, found: {:?}", got)
            }
            UnsupportedProtocolVersion(got) => write!(
                f,
                "Unsupported protocol version, expected: v5 found v{0}",
                got
            ),
            InvalidHandshakeCookie(expected, got) => write!(
                f,
                "Received invalid cookie, expected {}, got {}",
                expected, got
            ),
            SrtHandshakeExpected(got) => write!(
                f,
                "Expected SRT handshake request in conclusion handshake, found {:?}",
                got
            ),
        }
    }
}

impl Error for ListenError {}

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
        timestamp: TimeStamp,
        shake: HandshakeControlInfo,
    ) -> ListenResult {
        match shake.shake_type {
            ShakeType::Induction => {
                // https://tools.ietf.org/html/draft-gg-udt-03#page-9
                // When the server first receives the connection request from a client,
                // it generates a cookie value according to the client address and a
                // secret key and sends it back to the client. The client must then send
                // back the same cookie to the server.

                // generate the cookie, which is just a hash of the address + time
                let cookie = gen_cookie(&from);

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
        timestamp: TimeStamp,
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

    fn handle_control_packets(&mut self, control: ControlPacket, from: SocketAddr) -> ListenResult {
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
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
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
            Ok(Some(packet)) => sock.send(packet).await?,
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

#[cfg(test)]
mod test {
    use super::*;

    use std::net::IpAddr;

    use bytes::Bytes;
    use rand::random;

    use crate::packet::{ControlPacket, DataPacket, HandshakeControlInfo, Packet, ShakeType};

    fn test_listen() -> Listen {
        Listen::new(ListenConfiguration {
            local_socket_id: random(),
            tsbpd_latency: Duration::from_secs(1),
        })
    }

    fn test_induction() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: 1316,
            max_flow_size: 256_000,
            shake_type: ShakeType::Induction,
            socket_id: random(),
            syn_cookie: 0,
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVSInfo::V5 {
                crypto_size: 0,
                ext_hs: None,
                ext_km: None,
                ext_config: None,
            },
        }
    }

    fn test_conclusion() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: 1316,
            max_flow_size: 256_000,
            shake_type: ShakeType::Conclusion,
            socket_id: random(),
            syn_cookie: 0,
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVSInfo::V5 {
                crypto_size: 0,
                ext_hs: None,
                ext_km: None,
                ext_config: None,
            },
        }
    }

    fn build_hs_pack(i: HandshakeControlInfo) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: random(),
            control_type: ControlTypes::Handshake(i),
        })
    }

    #[test]
    fn send_data_packet() {
        let mut l = test_listen();

        let dp = DataPacket {
            seq_number: random(),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            message_number: random(),
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: random(),
            payload: Bytes::from(&b"asdf"[..]),
        };
        assert_eq!(
            l.handle_packet((Packet::Data(dp.clone()), "127.0.0.1:8765".parse().unwrap())),
            Err(ListenError::ControlExpected(ShakeType::Induction, dp))
        );
    }

    #[test]
    fn send_ack2() {
        let mut l = test_listen();

        let a2 = ControlTypes::Ack2(random());
        assert_eq!(
            l.handle_packet((
                Packet::Control(ControlPacket {
                    timestamp: TimeStamp::from_micros(0),
                    dest_sockid: random(),
                    control_type: a2.clone()
                }),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ListenError::HandshakeExpected(ShakeType::Induction, a2))
        );
    }

    #[test]
    fn send_wrong_handshake() {
        let mut l = test_listen();

        // listen expects an induction first, send a conclustion first

        let shake = test_conclusion();
        assert_eq!(
            l.handle_packet((
                build_hs_pack(shake.clone()),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ListenError::InductionExpected(shake))
        );
    }

    #[test]
    fn send_induction_twice() {
        let mut l = test_listen();

        // send a rendezvous handshake after an induction
        let resp = l.handle_packet((
            build_hs_pack(test_induction()),
            "127.0.0.1:8765".parse().unwrap(),
        ));
        assert!(resp.is_ok());
        assert!(resp.unwrap().is_some());

        let mut shake = test_induction();
        shake.shake_type = ShakeType::Waveahand;
        assert_eq!(
            l.handle_packet((
                build_hs_pack(shake.clone()),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ListenError::ConclusionExpected(shake))
        )
    }
}
