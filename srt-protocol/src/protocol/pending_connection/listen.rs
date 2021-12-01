use std::{net::SocketAddr, time::Instant};

use ConnectionResult::*;
use ListenState::*;

use crate::{connection::Connection, packet::*, protocol::handshake::Handshake, settings::*};

use super::{
    cookie::gen_cookie,
    hsv5::{gen_hsv5_response, GenHsv5Result},
    ConnectError, ConnectionReject, ConnectionResult,
};

pub struct Listen {
    init_settings: ConnInitSettings,
    state: ListenState,
}

#[derive(Clone)]
pub struct ConclusionWaitState {
    cookie: i32,
    induction_response: Packet,
    induction_time: Instant,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum ListenState {
    InductionWait,
    ConclusionWait(ConclusionWaitState),
}

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
        now: Instant,
    ) -> ConnectionResult {
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
                        info: HandshakeVsInfo::V5(HsV5Info::default()),
                        ..shake
                    }),
                });

                // save induction message for potential later retransmit
                let save_induction_response = induction_response.clone();
                self.state = ConclusionWait(ConclusionWaitState {
                    cookie,
                    induction_response: save_induction_response,
                    induction_time: now,
                });
                SendPacket((induction_response, from))
            }
            _ => NotHandled(ConnectError::InductionExpected(shake)),
        }
    }

    fn make_rejection(
        &self,
        response_to: &HandshakeControlInfo,
        from: SocketAddr,
        timestamp: TimeStamp,
        r: ConnectionReject,
    ) -> ConnectionResult {
        ConnectionResult::Reject(
            Some((
                ControlPacket {
                    timestamp,
                    dest_sockid: response_to.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Rejection(r.reason()),
                        socket_id: self.init_settings.local_sockid,
                        ..response_to.clone()
                    }),
                }
                .into(),
                from,
            )),
            r,
        )
    }

    fn wait_for_conclusion<A: StreamAcceptor>(
        &mut self,
        from: SocketAddr,
        timestamp: TimeStamp,
        state: ConclusionWaitState,
        shake: HandshakeControlInfo,
        now: Instant,
        acceptor: &mut A,
    ) -> ConnectionResult {
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
            (ShakeType::Induction, _, _) => SendPacket((state.induction_response, from)),
            // first induction received, wait for response (with cookie)
            (ShakeType::Conclusion, VERSION_5, syn_cookie) if syn_cookie == state.cookie => {
                // construct a packet to send back
                let (hsv5, settings) = match gen_hsv5_response(
                    &mut self.init_settings,
                    &shake,
                    from,
                    state.induction_time,
                    now,
                    acceptor,
                ) {
                    GenHsv5Result::Accept(h, c) => (h, c),
                    GenHsv5Result::NotHandled(e) => return NotHandled(e),
                    GenHsv5Result::Reject(r) => {
                        return self.make_rejection(&shake, from, timestamp, r);
                    }
                };

                let resp_handshake = ControlPacket {
                    timestamp,
                    dest_sockid: shake.socket_id,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        syn_cookie: state.cookie,
                        socket_id: self.init_settings.local_sockid,
                        info: hsv5,
                        shake_type: ShakeType::Conclusion,
                        ..shake // TODO: this will pass peer wrong
                    }),
                };

                // select the smaller packet size and max window size
                // TODO: allow configuration of these parameters, for now just
                // use the remote ones

                // finish the connection
                Connected(
                    Some((resp_handshake.clone().into(), from)),
                    Connection {
                        settings,
                        handshake: Handshake::Listener(resp_handshake.control_type),
                    },
                )
            }
            (ShakeType::Conclusion, VERSION_5, syn_cookie) => NotHandled(
                ConnectError::InvalidHandshakeCookie(state.cookie, syn_cookie),
            ),
            (ShakeType::Conclusion, version, _) => {
                NotHandled(ConnectError::UnsupportedProtocolVersion(version))
            }
            (_, _, _) => NotHandled(ConnectError::ConclusionExpected(shake)),
        }
    }

    fn handle_control_packets(
        &mut self,
        control: ControlPacket,
        from: SocketAddr,
        now: Instant,
        acceptor: &mut impl StreamAcceptor,
    ) -> ConnectionResult {
        match (self.state.clone(), control.control_type) {
            (InductionWait, ControlTypes::Handshake(shake)) => {
                self.wait_for_induction(from, control.timestamp, shake, now)
            }
            (ConclusionWait(state), ControlTypes::Handshake(shake)) => {
                self.wait_for_conclusion(from, control.timestamp, state, shake, now, acceptor)
            }
            (InductionWait, control_type) | (ConclusionWait(_), control_type) => {
                NotHandled(ConnectError::HandshakeExpected(control_type))
            }
        }
    }

    pub fn handle_packet(
        &mut self,
        packet: ReceivePacketResult,
        now: Instant,
        acceptor: &mut impl StreamAcceptor,
    ) -> ConnectionResult {
        match packet {
            Ok((packet, from)) => match packet {
                Packet::Control(control) => {
                    self.handle_control_packets(control, from, now, acceptor)
                }
                Packet::Data(data) => NotHandled(ConnectError::ControlExpected(data)),
            },
            Err(PacketParseError::Io(error)) => Failure(error),
            Err(e) => NotHandled(ConnectError::ParseFailed(e)),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use bytes::Bytes;
    use rand::random;

    use super::*;

    fn conn_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8765)
    }

    fn test_listen() -> (Listen, impl StreamAcceptor) {
        (
            Listen::new(ConnInitSettings::default()),
            AllowAllStreamAcceptor::default(),
        )
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
            info: HandshakeVsInfo::V5(HsV5Info::default()),
        }
    }

    fn test_conclusion() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: 1316,
            max_flow_size: 256_000,
            shake_type: ShakeType::Conclusion,
            socket_id: random(),
            syn_cookie: gen_cookie(&conn_addr()),
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info {
                crypto_size: 0,
                ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                    version: SrtVersion::CURRENT,
                    flags: SrtShakeFlags::SUPPORTED,
                    send_latency: Duration::from_secs(1),
                    recv_latency: Duration::from_secs(2),
                })),
                ext_km: None,
                ext_group: None,
                sid: None,
            }),
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
        let (mut l, mut a) = test_listen();

        let resp = l.handle_packet(
            Ok((build_hs_pack(test_induction()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(resp, SendPacket(_)));

        let resp = l.handle_packet(
            Ok((build_hs_pack(test_conclusion()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        // make sure it returns hs_ext
        assert!(
            matches!(
                resp,
                Connected(
                    Some(_),
                    Connection {
                        handshake: Handshake::Listener(ControlTypes::Handshake(
                            HandshakeControlInfo {
                                info: HandshakeVsInfo::V5(HsV5Info {
                                    ext_hs: Some(_),
                                    ..
                                }),
                                ..
                            }
                        )),
                        ..
                    },
                )
            ),
            "{:?}",
            resp
        );
    }

    #[test]
    fn send_data_packet() {
        let (mut l, mut a) = test_listen();

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
        assert!(matches!(
            l.handle_packet(Ok(( Packet::Data(dp.clone()), conn_addr())), Instant::now(), &mut a),
            NotHandled(ConnectError::ControlExpected(d)) if d == dp
        ));
    }

    #[test]
    fn send_ack2() {
        let (mut l, mut a) = test_listen();

        let a2 = ControlTypes::Ack2(FullAckSeqNumber::new(random::<u32>() + 1).unwrap());
        assert!(matches!(
            l.handle_packet(Ok((
                Packet::Control(ControlPacket {
                    timestamp: TimeStamp::from_micros(0),
                    dest_sockid: random(),
                    control_type: a2.clone()
                }),
                conn_addr()
            )), Instant::now(), &mut a),
            NotHandled(ConnectError::HandshakeExpected(pack)) if pack == a2
        ));
    }

    #[test]
    fn send_wrong_handshake() {
        let (mut l, mut a) = test_listen();

        // listen expects an induction first, send a conclustion first

        let shake = test_conclusion();
        assert!(matches!(
            l.handle_packet(Ok((
                build_hs_pack(shake.clone()),
                conn_addr()
            )), Instant::now(), &mut a),
            NotHandled(ConnectError::InductionExpected(s)) if s == shake
        ));
    }

    #[test]
    fn send_induction_twice() {
        let (mut l, mut a) = test_listen();

        // send a rendezvous handshake after an induction
        let resp = l.handle_packet(
            Ok((build_hs_pack(test_induction()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(resp, SendPacket(_)));

        let mut shake = test_induction();
        shake.shake_type = ShakeType::Waveahand;
        assert!(matches!(
            l.handle_packet(Ok((
                build_hs_pack(shake.clone()),
                conn_addr()
            )), Instant::now(), &mut a),
            NotHandled(ConnectError::ConclusionExpected(nc)) if nc == shake
        ))
    }

    #[test]
    fn send_v4_conclusion() {
        let (mut l, mut a) = test_listen();

        let resp = l.handle_packet(
            Ok((build_hs_pack(test_induction()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(resp, SendPacket(_)));

        let mut c = test_conclusion();
        c.info = HandshakeVsInfo::V4(SocketType::Datagram);

        let resp = l.handle_packet(Ok((build_hs_pack(c), conn_addr())), Instant::now(), &mut a);

        assert!(
            matches!(
                resp,
                NotHandled(ConnectError::UnsupportedProtocolVersion(4))
            ),
            "{:?}",
            resp
        );
    }

    #[test]
    fn send_no_ext_hs_conclusion() {
        let (mut l, mut a) = test_listen();

        let resp = l.handle_packet(
            Ok((build_hs_pack(test_induction()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(resp, SendPacket(_)));

        let mut c = test_conclusion();
        c.info = HandshakeVsInfo::V5(HsV5Info::default());

        let resp = l.handle_packet(Ok((build_hs_pack(c), conn_addr())), Instant::now(), &mut a);

        assert!(
            matches!(resp, NotHandled(ConnectError::ExpectedExtFlags)),
            "{:?}",
            resp
        );
    }
    struct Rejector;
    impl StreamAcceptor for Rejector {
        fn accept(
            &mut self,
            _streamid: Option<&str>,
            _ip: SocketAddr,
        ) -> Result<AcceptParameters, RejectReason> {
            Err(RejectReason::Server(ServerRejectReason::Overload))
        }
    }

    #[test]
    fn reject() {
        let (mut l, _) = test_listen();
        let mut a = Rejector;
        let resp = l.handle_packet(
            Ok((build_hs_pack(test_induction()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(resp, SendPacket(_)));

        let resp = l.handle_packet(
            Ok((build_hs_pack(test_conclusion()), conn_addr())),
            Instant::now(),
            &mut a,
        );
        assert!(matches!(
            resp,
            Reject(
                _,
                ConnectionReject::Rejecting(RejectReason::Server(ServerRejectReason::Overload)),
            )
        ));
    }
}
