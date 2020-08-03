use std::net::SocketAddr;

use crate::packet::*;
use crate::protocol::TimeStamp;
use crate::{ConnectionSettings, SocketID};

use super::{cookie::gen_cookie, hsv5::gen_hsv5_response, ConnInitSettings, ConnectError};
use ConnectError::*;
use ListenState::*;

pub struct Listen {
    init_settings: ConnInitSettings,
    state: ListenState,
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

type ListenResult = Result<Option<(Packet, SocketAddr)>, ConnectError>;

impl Listen {
    pub fn new(init_settings: ConnInitSettings) -> Listen {
        Listen {
            state: InductionWait,
            init_settings,
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
                        socket_id: self.init_settings.local_sockid,
                        info: HandshakeVSInfo::V5 {
                            crypto_size: 0,
                            ext_hs: None,
                            ext_km: None,
                            ext_config: None,
                        },
                        init_seq_num: self.init_settings.starting_send_seqnum,
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
                // construct a packet to send back
                let (hsv5, connection) =
                    gen_hsv5_response(self.init_settings.clone(), &shake, from)?;

                let resp_handshake = ControlPacket {
                    timestamp,
                    dest_sockid: shake.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        syn_cookie: state.cookie,
                        socket_id: self.init_settings.local_sockid,
                        info: hsv5,
                        // srt/srtcore/core.cpp
                        // void CUDT::acceptAndRespond(...)
                        // {
                        //    ...
                        //    // use peer's ISN and send it back for security check
                        //    m_iISN = hs->m_iISN;
                        //    ...
                        // }
                        init_seq_num: shake.init_seq_num,
                        shake_type: ShakeType::Conclusion,
                        ..shake // TODO: this will pass peer wrong
                    }),
                };

                // select the smaller packet size and max window size
                // TODO: allow configuration of these parameters, for now just
                // use the remote ones

                // finish the connection
                self.state = Connected(resp_handshake.clone(), connection);

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
            (ConclusionWait(state), ControlTypes::Handshake(shake)) => {
                self.wait_for_conclusion(from, control.timestamp, state, shake)
            }
            (InductionWait, control_type) | (ConclusionWait(_), control_type) => {
                Err(HandshakeExpected(control_type))
            }
            (Connected(_, _), _) => Ok(None),
        }
    }

    pub fn handle_packet(&mut self, (packet, from): (Packet, SocketAddr)) -> ListenResult {
        match packet {
            Packet::Control(control) => self.handle_control_packets(control, from),
            Packet::Data(data) => Err(ControlExpected(data)),
        }
    }

    pub fn state(&self) -> &ListenState {
        &self.state
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{net::IpAddr, time::Duration};

    use bytes::Bytes;
    use rand::random;

    use crate::{
        packet::{ControlPacket, DataPacket, HandshakeControlInfo, Packet, ShakeType},
        SrtVersion,
    };

    fn test_listen() -> Listen {
        Listen::new(ConnInitSettings::default())
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
            syn_cookie: gen_cookie(&"127.0.0.1:8765".parse().unwrap()),
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVSInfo::V5 {
                crypto_size: 0,
                ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                    version: SrtVersion::CURRENT,
                    flags: SrtShakeFlags::SUPPORTED,
                    send_latency: Duration::from_secs(1),
                    recv_latency: Duration::from_secs(2),
                })),
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
    fn correct() {
        let mut l = test_listen();

        let resp = l.handle_packet((
            build_hs_pack(test_induction()),
            "127.0.0.1:8765".parse().unwrap(),
        ));
        assert!(matches!(resp, Ok(Some(_))));

        let resp = l.handle_packet((
            build_hs_pack(test_conclusion()),
            "127.0.0.1:8765".parse().unwrap(),
        ));
        // make sure it returns hs_ext
        assert!(matches!(resp,
            Ok(Some((Packet::Control(ControlPacket{control_type: ControlTypes::Handshake(HandshakeControlInfo{info: HandshakeVSInfo::V5{ext_hs: Some(_), ..}, ..}), ..}), _)))), "{:?}", resp
        );
    }

    #[test]
    fn send_data_packet() {
        let mut l = test_listen();

        let dp = DataPacket {
            seq_number: random(),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: random(),
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: random(),
            payload: Bytes::from(&b"asdf"[..]),
        };
        assert!(
            matches!(
                l.handle_packet((Packet::Data(dp.clone()), "127.0.0.1:8765".parse().unwrap())),
                Err(ConnectError::ControlExpected(d)) if d == dp
            )
        );
    }

    #[test]
    fn send_ack2() {
        let mut l = test_listen();

        let a2 = ControlTypes::Ack2(random());
        assert!(matches!(
            l.handle_packet((
                Packet::Control(ControlPacket {
                    timestamp: TimeStamp::from_micros(0),
                    dest_sockid: random(),
                    control_type: a2.clone()
                }),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ConnectError::HandshakeExpected(pack)) if pack == a2
        ));
    }

    #[test]
    fn send_wrong_handshake() {
        let mut l = test_listen();

        // listen expects an induction first, send a conclustion first

        let shake = test_conclusion();
        assert!(matches!(
            l.handle_packet((
                build_hs_pack(shake.clone()),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ConnectError::InductionExpected(s)) if s == shake
        ));
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
        assert!(matches!(
            l.handle_packet((
                build_hs_pack(shake.clone()),
                "127.0.0.1:8765".parse().unwrap()
            )),
            Err(ConnectError::ConclusionExpected(nc)) if nc == shake
        ))
    }

    #[test]
    fn send_v4_conclusion() {
        let mut l = test_listen();

        let resp = l.handle_packet((
            build_hs_pack(test_induction()),
            "127.0.0.1:8765".parse().unwrap(),
        ));
        assert!(matches!(resp, Ok(Some(_))));

        let mut c = test_conclusion();
        c.info = HandshakeVSInfo::V4(SocketType::Datagram);

        let resp = l.handle_packet((build_hs_pack(c), "127.0.0.1:8765".parse().unwrap()));

        assert!(
            matches!(resp, Err(ConnectError::UnsupportedProtocolVersion(4))),
            "{:?}",
            resp
        );
    }

    #[test]
    fn send_no_ext_hs_conclusion() {
        let mut l = test_listen();

        let resp = l.handle_packet((
            build_hs_pack(test_induction()),
            "127.0.0.1:8765".parse().unwrap(),
        ));
        assert!(matches!(resp, Ok(Some(_))));

        let mut c = test_conclusion();
        c.info = HandshakeVSInfo::V5 {
            crypto_size: 0,
            ext_hs: None,
            ext_km: None,
            ext_config: None,
        };

        let resp = l.handle_packet((build_hs_pack(c), "127.0.0.1:8765".parse().unwrap()));

        assert!(
            matches!(resp, Err(ConnectError::ExpectedExtFlags)),
            "{:?}",
            resp
        );
    }
}
