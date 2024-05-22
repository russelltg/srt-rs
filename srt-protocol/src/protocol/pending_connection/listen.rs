use std::{convert::TryInto, net::SocketAddr, time::Instant};

use crate::{packet::*, protocol::handshake::Handshake, settings::*};

use super::{
    cookie::gen_cookie, hsv5::gen_access_control_response, hsv5::GenHsv5Result,
    AccessControlRequest, AccessControlResponse, ConnectError, Connection, ConnectionReject,
    ConnectionResult,
};

use ConnectionResult::*;
use ListenState::*;

#[derive(Debug)]
pub struct Listen {
    init_settings: ConnInitSettings,
    state: ListenState,
    enable_access_control: bool,
}

#[derive(Clone, Debug)]
pub struct ConclusionWaitState {
    from: SocketAddr,
    cookie: i32,
    induction_response: Packet,
    induction_time: Instant,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum ListenState {
    InductionWait,
    ConclusionWait(ConclusionWaitState),
    AccessControlRequested(
        ConclusionWaitState,
        TimeStamp,
        HandshakeControlInfo,
        HsV5Info,
    ),
}

impl Listen {
    pub fn new(init_settings: ConnInitSettings, enable_access_control: bool) -> Listen {
        Listen {
            state: InductionWait,
            init_settings,
            enable_access_control,
        }
    }

    pub fn settings(&self) -> &ConnInitSettings {
        &self.init_settings
    }

    pub fn handle_packet(&mut self, now: Instant, packet: ReceivePacketResult) -> ConnectionResult {
        use ReceivePacketError::*;
        match packet {
            Ok((packet, from)) => match packet {
                Packet::Control(control) => self.handle_control_packets(now, from, control),
                Packet::Data(data) => NotHandled(ConnectError::ControlExpected(data)),
            },
            Err(Io(error)) => Failure(error),
            Err(Parse(e)) => NotHandled(ConnectError::ParseFailed(e)),
        }
    }

    pub fn handle_access_control_response(
        &mut self,
        now: Instant,
        response: AccessControlResponse,
    ) -> ConnectionResult {
        match self.state.clone() {
            // TODO: something other than ExpectedHsReq
            InductionWait | ConclusionWait(_) => NotHandled(ConnectError::ExpectedHsReq),
            AccessControlRequested(state, timestamp, shake, info) => {
                use AccessControlResponse::*;
                match response {
                    Accepted(key_settings) => {
                        self.accept_connection(now, &state, timestamp, shake, info, key_settings)
                    }
                    Rejected(rr) => self.make_rejection(
                        &shake,
                        state.from,
                        timestamp,
                        ConnectionReject::Rejecting(rr),
                    ),
                    Dropped => self.make_rejection(
                        &shake,
                        state.from,
                        timestamp,
                        ConnectionReject::Rejecting(RejectReason::Core(CoreRejectReason::Peer)),
                    ),
                }
            }
        }
    }

    pub fn handle_timer(&self, _now: Instant) -> ConnectionResult {
        ConnectionResult::NoAction
    }

    fn handle_control_packets(
        &mut self,
        now: Instant,
        from: SocketAddr,
        control: ControlPacket,
    ) -> ConnectionResult {
        match (self.state.clone(), control.control_type) {
            (InductionWait, ControlTypes::Handshake(shake)) => {
                self.wait_for_induction(from, control.timestamp, shake, now)
            }
            (ConclusionWait(state), ControlTypes::Handshake(shake)) => self.wait_for_conclusion(
                now,
                from,
                control.dest_sockid,
                control.timestamp,
                state,
                shake,
            ),
            (AccessControlRequested(_, _, _, _), _) => {
                NotHandled(ConnectError::ExpectedAccessControlResponse)
            }
            (InductionWait, control_type) | (ConclusionWait(_), control_type) => {
                NotHandled(ConnectError::HandshakeExpected(control_type))
            }
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
                    from,
                    cookie,
                    induction_response: save_induction_response,
                    induction_time: now,
                });
                SendPacket((induction_response, from))
            }
            _ => NotHandled(ConnectError::InductionExpected(shake)),
        }
    }

    fn wait_for_conclusion(
        &mut self,
        now: Instant,
        from: SocketAddr,
        local_socket_id: SocketId,
        timestamp: TimeStamp,
        state: ConclusionWaitState,
        shake: HandshakeControlInfo,
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
                let incoming = match &shake.info {
                    HandshakeVsInfo::V5(hs) => hs,
                    _ => {
                        let r = ConnectionReject::Rejecting(
                            // TODO: this error is technically reserved for access control handlers, as the ref impl supports hsv4+5, while we only support 5
                            ServerRejectReason::Version.into(),
                        );
                        return self.make_rejection(&shake, from, timestamp, r);
                    }
                }
                .clone();

                if self.enable_access_control {
                    self.request_access(from, local_socket_id, timestamp, state, shake, incoming)
                } else {
                    let key_settings = self.settings().key_settings.clone();
                    self.accept_connection(now, &state, timestamp, shake, incoming, key_settings)
                }
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

    fn request_access(
        &mut self,
        remote: SocketAddr,
        local_socket_id: SocketId,
        timestamp: TimeStamp,
        state: ConclusionWaitState,
        shake: HandshakeControlInfo,
        incoming: HsV5Info,
    ) -> ConnectionResult {
        // TODO: handle StreamId parsing error
        let stream_id = incoming.sid.clone().and_then(|s| s.try_into().ok());
        let remote_socket_id = shake.socket_id;
        let key_size = incoming.key_size;

        self.state = AccessControlRequested(state, timestamp, shake, incoming);

        RequestAccess(AccessControlRequest {
            local_socket_id,
            remote,
            remote_socket_id,
            stream_id,
            key_size,
        })
    }

    fn accept_connection(
        &mut self,
        now: Instant,
        state: &ConclusionWaitState,
        timestamp: TimeStamp,
        shake: HandshakeControlInfo,
        info: HsV5Info,
        key_settings: Option<KeySettings>,
    ) -> ConnectionResult {
        let response = gen_access_control_response(
            now,
            &mut self.init_settings,
            state.from,
            state.induction_time,
            shake.clone(),
            info,
            key_settings,
        );
        let (hsv5, settings) = match response {
            GenHsv5Result::Accept(h, c) => (h, c),
            GenHsv5Result::NotHandled(e) => return NotHandled(e),
            GenHsv5Result::Reject(r) => {
                return self.make_rejection(&shake, state.from, timestamp, r);
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

        // finish the connection
        Connected(
            Some((resp_handshake.clone().into(), state.from)),
            Connection {
                settings,
                handshake: Handshake::Listener(resp_handshake.control_type),
            },
        )
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
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use assert_matches::assert_matches;
    use bytes::Bytes;
    use rand::random;

    use crate::options::*;

    use super::*;

    fn conn_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8765)
    }

    fn test_listen() -> Listen {
        Listen::new(ConnInitSettings::default(), false)
    }

    fn test_induction() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: PacketSize(1316),
            max_flow_size: PacketCount(256_000),
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
            max_packet_size: PacketSize(1316),
            max_flow_size: PacketCount(256_000),
            shake_type: ShakeType::Conclusion,
            socket_id: random(),
            syn_cookie: gen_cookie(&conn_addr()),
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info {
                key_size: KeySize::Unspecified,
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
        let mut l = test_listen();

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_induction()), conn_addr())),
        );
        assert_matches!(resp, SendPacket(_));

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_conclusion()), conn_addr())),
        );
        // make sure it returns hs_ext
        assert_matches!(
            resp,
            Connected(
                Some(_),
                Connection {
                    handshake: Handshake::Listener(ControlTypes::Handshake(HandshakeControlInfo {
                        info: HandshakeVsInfo::V5(HsV5Info {
                            ext_hs: Some(_),
                            ..
                        }),
                        ..
                    })),
                    ..
                },
            )
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
        assert_matches!(
            l.handle_packet(Instant::now(), Ok(( Packet::Data(dp.clone()), conn_addr()))),
            NotHandled(ConnectError::ControlExpected(d)) if d == dp
        );
    }

    #[test]
    fn send_ack2() {
        let mut l = test_listen();

        let a2 = ControlTypes::Ack2(FullAckSeqNumber::new(random::<u32>() + 1).unwrap());
        assert_matches!(
            l.handle_packet(Instant::now(),
                Ok((
                    Packet::Control(ControlPacket {
                        timestamp: TimeStamp::from_micros(0),
                        dest_sockid: random(),
                        control_type: a2.clone()
                    }),
                    conn_addr()
                )),
            ),
            NotHandled(ConnectError::HandshakeExpected(pack)) if pack == a2
        );
    }

    #[test]
    fn send_wrong_handshake() {
        let mut l = test_listen();

        // listen expects an induction first, send a conclustion first

        let shake = test_conclusion();
        assert_matches!(
            l.handle_packet(Instant::now(), Ok((
                build_hs_pack(shake.clone()),
                conn_addr()
            ))),
            NotHandled(ConnectError::InductionExpected(s)) if s == shake
        );
    }

    #[test]
    fn send_induction_twice() {
        let mut l = test_listen();

        // send a rendezvous handshake after an induction
        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_induction()), conn_addr())),
        );
        assert_matches!(resp, SendPacket(_));

        let mut shake = test_induction();
        shake.shake_type = ShakeType::Waveahand;
        assert_matches!(
            l.handle_packet(Instant::now(), Ok((
                build_hs_pack(shake.clone()),
                conn_addr()
            ))),
            NotHandled(ConnectError::ConclusionExpected(nc)) if nc == shake
        )
    }

    #[test]
    fn send_v4_conclusion() {
        let mut l = test_listen();

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_induction()), conn_addr())),
        );
        assert_matches!(resp, SendPacket(_));

        let mut c = test_conclusion();
        c.info = HandshakeVsInfo::V4(SocketType::Datagram);

        let resp = l.handle_packet(Instant::now(), Ok((build_hs_pack(c), conn_addr())));

        assert_matches!(
            resp,
            NotHandled(ConnectError::UnsupportedProtocolVersion(4))
        );
    }

    #[test]
    fn send_no_ext_hs_conclusion() {
        let mut l = test_listen();

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_induction()), conn_addr())),
        );
        assert_matches!(resp, SendPacket(_));

        let mut c = test_conclusion();
        c.info = HandshakeVsInfo::V5(HsV5Info::default());

        let resp = l.handle_packet(Instant::now(), Ok((build_hs_pack(c), conn_addr())));

        assert_matches!(resp, NotHandled(ConnectError::ExpectedExtFlags));
    }

    #[test]
    fn reject() {
        let mut l = Listen::new(ConnInitSettings::default(), true);

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_induction()), conn_addr())),
        );
        assert_matches!(resp, SendPacket(_));

        let resp = l.handle_packet(
            Instant::now(),
            Ok((build_hs_pack(test_conclusion()), conn_addr())),
        );
        assert_matches!(resp, RequestAccess(_));

        let resp = l.handle_access_control_response(
            Instant::now(),
            AccessControlResponse::Rejected(RejectReason::Server(ServerRejectReason::Overload)),
        );
        assert_matches!(
            resp,
            Reject(
                _,
                ConnectionReject::Rejecting(RejectReason::Server(ServerRejectReason::Overload)),
            )
        );
    }
}
