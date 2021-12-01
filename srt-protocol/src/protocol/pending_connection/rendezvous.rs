use std::{cmp::Ordering, net::SocketAddr, time::Instant};

use log::debug;

use ConnectError::*;
use ConnectionResult::*;
use RendezvousHsV5::*;
use RendezvousState::*;

use crate::{
    connection::{Connection, ConnectionSettings},
    packet::*,
    protocol::handshake::Handshake,
    settings::*,
};

use super::{
    cookie::gen_cookie,
    hsv5::{gen_hsv5_response, start_hsv5_initiation, GenHsv5Result, StartedInitiator},
    ConnectError, ConnectionReject, ConnectionResult,
};

pub struct Rendezvous {
    init_settings: ConnInitSettings,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    state: RendezvousState,
    cookie: i32,
    last_packet: (Packet, SocketAddr),
    last_send: Option<Instant>,
    starting_seqnum: SeqNumber,
}

// see haivision/srt/docs/handshake.md for documentation

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RendezvousState {
    Waving,
    AttentionInitiator(HandshakeVsInfo, StartedInitiator),
    AttentionResponder(Instant),            // induction time
    InitiatedResponder(ConnectionSettings), // responders always have the handshake when they transition to initiated
    InitiatedInitiator(StartedInitiator),
    FineResponder(ConnectionSettings),
    FineInitiator(HandshakeVsInfo, StartedInitiator),
}

impl Rendezvous {
    pub fn new(
        local_addr: SocketAddr,
        remote_public: SocketAddr,
        init_settings: ConnInitSettings,
        starting_seqnum: SeqNumber,
    ) -> Self {
        let cookie = gen_cookie(&local_addr);
        let last_packet = (
            ControlPacket {
                dest_sockid: SocketId(0),
                timestamp: TimeStamp::from_micros(0),
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num: starting_seqnum,
                    max_packet_size: 1500, // TODO: take as a parameter
                    max_flow_size: 8192,   // TODO: take as a parameter
                    socket_id: init_settings.local_sockid,
                    shake_type: ShakeType::Waveahand,
                    peer_addr: local_addr.ip(),
                    syn_cookie: cookie, // TODO: !!
                    info: Rendezvous::empty_flags(),
                }),
            }
            .into(),
            remote_public,
        );

        Self {
            state: Waving,
            cookie,
            last_packet,
            init_settings,
            local_addr,
            remote_public,
            last_send: None,
            starting_seqnum,
        }
    }
}

#[derive(Debug, Clone)]
enum RendezvousHsV5 {
    Initiator,
    Responder,
}

fn get_handshake(packet: &Packet) -> Result<&HandshakeControlInfo, ConnectError> {
    match packet {
        Packet::Control(ControlPacket {
            control_type: ControlTypes::Handshake(info),
            ..
        }) => Ok(info),
        Packet::Control(ControlPacket { control_type, .. }) => {
            Err(HandshakeExpected(control_type.clone()))
        }
        Packet::Data(data) => Err(ControlExpected(data.clone())),
    }
}

fn extract_ext_info(
    info: &HandshakeControlInfo,
) -> Result<Option<&SrtControlPacket>, ConnectError> {
    match &info.info {
        HandshakeVsInfo::V5(hs) => Ok(hs.ext_hs.as_ref()),
        _ => Err(UnsupportedProtocolVersion(4)),
    }
}

impl Rendezvous {
    fn empty_flags() -> HandshakeVsInfo {
        HandshakeVsInfo::V5(HsV5Info::default())
    }

    fn transition(&mut self, state: RendezvousState) {
        debug!(
            "Rendezvous {:?} transitioning from {:?} to {:?}",
            self.init_settings.local_sockid, self.state, state,
        );
        self.state = state
    }

    fn gen_packet(&self, shake_type: ShakeType, info: HandshakeVsInfo) -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: self.starting_seqnum,
            max_packet_size: 1500, // TODO: take as a parameter
            max_flow_size: 8192,   // TODO: take as a parameter
            socket_id: self.init_settings.local_sockid,
            shake_type,
            peer_addr: self.local_addr.ip(),
            syn_cookie: self.cookie, // TODO: !!
            info,
        }
    }

    fn send(&mut self, dest_sockid: SocketId, packet: HandshakeControlInfo) -> ConnectionResult {
        let pack_pair = (
            ControlPacket {
                timestamp: TimeStamp::from_micros(0),
                dest_sockid,
                control_type: ControlTypes::Handshake(packet),
            }
            .into(),
            self.remote_public,
        );
        self.last_packet = pack_pair.clone();
        SendPacket(pack_pair)
    }

    fn send_conclusion(
        &mut self,
        dest_sockid: SocketId,
        info: HandshakeVsInfo,
    ) -> ConnectionResult {
        self.send(dest_sockid, self.gen_packet(ShakeType::Conclusion, info))
    }

    // fn send_agreement(&mut self, dest_sockid: SocketID, info: HandshakeVSInfo) -> ConnectionResult {
    //     self.send(dest_sockid, self.gen_packet(ShakeType::Agreement, info))
    // }

    fn make_rejection(
        &self,
        response_to: &HandshakeControlInfo,
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
                self.remote_public,
            )),
            r,
        )
    }

    fn set_connected(
        &self,
        settings: ConnectionSettings,
        agreement: Option<HandshakeControlInfo>,
        to_send: Option<HandshakeControlInfo>,
    ) -> ConnectionResult {
        Connected(
            to_send.map(|to_send| {
                (
                    ControlPacket {
                        timestamp: TimeStamp::from_micros(0),
                        dest_sockid: settings.remote_sockid,
                        control_type: ControlTypes::Handshake(to_send),
                    }
                    .into(),
                    self.remote_public,
                )
            }),
            Connection {
                settings,
                handshake: Handshake::Rendezvous(agreement.map(ControlTypes::Handshake)),
            },
        )
    }

    fn handle_waving(
        &mut self,
        info: &HandshakeControlInfo,
        timestamp: TimeStamp,
        now: Instant,
    ) -> ConnectionResult {
        assert!(matches!(self.state, Waving));

        // NOTE: the cookie comparison behavior is not correctly documented. See haivision/srt#1267
        let role = match self.cookie.wrapping_sub(info.syn_cookie).cmp(&0) {
            Ordering::Greater => Initiator,
            Ordering::Less => Responder,
            Ordering::Equal => return NotHandled(CookiesMatched(self.cookie)),
        };

        debug!(
            "Rendezvous socket {:?} is {:?}",
            self.init_settings.local_sockid, role
        );

        match (info.shake_type, role) {
            (ShakeType::Waveahand, Initiator) => {
                // NOTE: streamid not supported in rendezvous
                let (hsv5, initiator) =
                    start_hsv5_initiation(self.init_settings.clone(), None, now);

                self.transition(AttentionInitiator(hsv5.clone(), initiator));

                self.send_conclusion(info.socket_id, hsv5)
            }
            (ShakeType::Waveahand, Responder) => {
                self.starting_seqnum = info.init_seq_num; // responder, take initiator's seqnum
                self.transition(AttentionResponder(now));
                self.send_conclusion(info.socket_id, Rendezvous::empty_flags())
            }
            (ShakeType::Conclusion, role) => {
                let ext_info = match extract_ext_info(info) {
                    Ok(ei) => ei,
                    Err(e) => return NotHandled(e),
                };
                let hsv5_shake = match (&role, ext_info) {
                    (Responder, Some(SrtControlPacket::HandshakeRequest(_))) => {
                        let (hsv5, connection) = match gen_hsv5_response(
                            &mut self.init_settings,
                            info,
                            self.remote_public,
                            match self.last_send {
                                Some(induction_time) => induction_time,
                                None => {
                                    return ConnectionResult::NotHandled(
                                        ConnectError::WaveahandExpected(info.clone()),
                                    );
                                }
                            },
                            now,
                            &mut AllowAllStreamAcceptor::default(),
                        ) {
                            GenHsv5Result::Accept(h, c) => (h, c),
                            GenHsv5Result::NotHandled(e) => return NotHandled(e),
                            GenHsv5Result::Reject(r) => {
                                return self.make_rejection(info, timestamp, r)
                            }
                        };
                        self.starting_seqnum = info.init_seq_num; // responder, take initiator's seqnum
                        self.transition(FineResponder(connection));

                        hsv5
                    }
                    (Initiator, None) => {
                        let (hsv5, initiator) =
                            start_hsv5_initiation(self.init_settings.clone(), None, now); // NOTE: streamid not supported in rendezvous
                        self.transition(FineInitiator(hsv5.clone(), initiator));
                        hsv5
                    }
                    (Responder, Some(_)) => {
                        return NotHandled(ExpectedHsReq);
                    }
                    (Initiator, Some(_)) => return NotHandled(ExpectedNoExtFlags),
                    (Responder, None) => return NotHandled(ExpectedExtFlags),
                };
                self.send_conclusion(info.socket_id, hsv5_shake)
            }
            (ShakeType::Agreement, _) => NoAction,
            (ShakeType::Induction, _) => NotHandled(RendezvousExpected(info.clone())),
            (ShakeType::Rejection(rej), _) => Reject(None, ConnectionReject::Rejected(rej)),
        }
    }

    fn handle_attention_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        hsv5: HandshakeVsInfo,
        initiator: StartedInitiator,
        now: Instant,
    ) -> ConnectionResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info) {
                Ok(Some(SrtControlPacket::HandshakeResponse(_))) => {
                    let agreement =
                        self.gen_packet(ShakeType::Agreement, Rendezvous::empty_flags());

                    let settings =
                        match initiator.finish_hsv5_initiation(info, self.remote_public, now) {
                            Ok(s) => s,
                            Err(r) => return NotHandled(r),
                        };

                    self.set_connected(settings, Some(agreement.clone()), Some(agreement))
                }
                Ok(Some(_)) => NotHandled(ExpectedHsResp),
                Ok(None) => {
                    self.transition(InitiatedInitiator(initiator));
                    self.send_conclusion(info.socket_id, hsv5)
                }
                Err(e) => NotHandled(e),
            },
            _ => NoAction, // todo: errors
        }
    }

    fn handle_attention_responder(
        &mut self,
        info: &HandshakeControlInfo,
        timestamp: TimeStamp,
        induction_time: Instant,
        now: Instant,
    ) -> ConnectionResult {
        match info.shake_type {
            ShakeType::Conclusion => {
                match extract_ext_info(info) {
                    Ok(Some(SrtControlPacket::HandshakeRequest(_))) => {} // ok, continue
                    Ok(Some(_)) => return NotHandled(ExpectedHsReq),
                    Ok(None) => return NotHandled(ExpectedExtFlags),
                    Err(e) => return NotHandled(e),
                };
                let (hsv5, connection) = match gen_hsv5_response(
                    &mut self.init_settings,
                    info,
                    self.remote_public,
                    induction_time,
                    now,
                    &mut AllowAllStreamAcceptor::default(),
                ) {
                    GenHsv5Result::Accept(h, c) => (h, c),
                    GenHsv5Result::NotHandled(e) => return NotHandled(e),
                    GenHsv5Result::Reject(r) => return self.make_rejection(info, timestamp, r),
                };
                self.starting_seqnum = info.init_seq_num; // responder, take initiator's seqnum
                self.transition(InitiatedResponder(connection));

                self.send_conclusion(info.socket_id, hsv5)
            }
            _ => NoAction,
        }
    }

    fn handle_fine_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        hsv5: HandshakeVsInfo,
        initiator: StartedInitiator,
        now: Instant,
    ) -> ConnectionResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info) {
                Ok(Some(SrtControlPacket::HandshakeResponse(_))) => {
                    let agreement = self.gen_packet(ShakeType::Agreement, hsv5);

                    let settings =
                        match initiator.finish_hsv5_initiation(info, self.remote_public, now) {
                            Ok(s) => s,
                            Err(r) => return NotHandled(r),
                        };

                    self.set_connected(settings, Some(agreement.clone()), Some(agreement))
                }
                Ok(Some(_)) => NotHandled(ExpectedHsResp),
                Ok(None) => NotHandled(ExpectedExtFlags),
                Err(e) => NotHandled(e),
            },
            _ => NoAction, // real errors here
        }
    }

    fn handle_fine_responder(
        &mut self,
        packet: &Packet,
        connection: ConnectionSettings,
    ) -> ConnectionResult {
        match packet {
            Packet::Data(_)
            | Packet::Control(ControlPacket {
                control_type:
                    ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Agreement,
                        ..
                    }),
                ..
            })
            | Packet::Control(ControlPacket {
                control_type: ControlTypes::KeepAlive,
                ..
            }) => return self.set_connected(connection, None, None),
            _ => {}
        }
        NoAction
    }

    fn handle_initiated_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        initiator: StartedInitiator,
        now: Instant,
    ) -> ConnectionResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info) {
                Ok(Some(SrtControlPacket::HandshakeResponse(_))) => {
                    let connection =
                        match initiator.finish_hsv5_initiation(info, self.remote_public, now) {
                            Ok(c) => c,
                            Err(e) => return NotHandled(e),
                        };

                    let agreement =
                        self.gen_packet(ShakeType::Agreement, Rendezvous::empty_flags());

                    // TODO: not sure if this should return Some for agreement. A test was failing without it but check spec
                    self.set_connected(connection, Some(agreement.clone()), Some(agreement))
                }
                Ok(Some(_)) => NotHandled(ExpectedHsResp),
                Ok(None) => NotHandled(ExpectedExtFlags), // spec says stay in this state
                Err(e) => NotHandled(e),
            },
            _ => NoAction, // real errors here
        }
    }

    fn handle_initiated_responder(
        &mut self,
        packet: &Packet,
        connection: ConnectionSettings,
    ) -> ConnectionResult {
        // if the shake still has flags, respond with flags and don't finish.
        if let Ok(info) = get_handshake(packet) {
            match (info.shake_type, extract_ext_info(info)) {
                (_, Err(e)) => return NotHandled(e),
                (ShakeType::Conclusion, Ok(Some(SrtControlPacket::HandshakeRequest(_)))) => {
                    return NoAction; // TODO: this is a pretty roundabout way to do this...just waits for another tick
                }
                (ShakeType::Conclusion, Ok(Some(_))) => return NotHandled(ExpectedHsReq),
                (ShakeType::Waveahand, _) => return NotHandled(AgreementExpected(info.clone())),
                _ => {}
            }
        }

        self.set_connected(
            connection,
            None,
            Some(self.gen_packet(ShakeType::Agreement, Rendezvous::empty_flags())),
        )
    }

    pub fn handle_packet(&mut self, packet: ReceivePacketResult, now: Instant) -> ConnectionResult {
        match packet {
            Ok((packet, from)) => {
                if from != self.remote_public {
                    return NotHandled(UnexpectedHost(self.remote_public, from));
                }

                let hs = get_handshake(&packet);
                match (self.state.clone(), hs) {
                    (Waving, Ok(hs)) => self.handle_waving(hs, packet.timestamp(), now),
                    (AttentionInitiator(hsv5, initiator), Ok(hs)) => {
                        self.handle_attention_initiator(hs, hsv5, initiator, now)
                    }
                    (AttentionResponder(induction_time), Ok(hs)) => {
                        self.handle_attention_responder(hs, packet.timestamp(), induction_time, now)
                    }
                    (InitiatedInitiator(initiator), Ok(hs)) => {
                        self.handle_initiated_initiator(hs, initiator, now)
                    }
                    (InitiatedResponder(connection), _) => {
                        self.handle_initiated_responder(&packet, connection)
                    }
                    (FineInitiator(hsv5, initiator), Ok(hs)) => {
                        self.handle_fine_initiator(hs, hsv5, initiator, now)
                    }
                    (FineResponder(conn), _) => self.handle_fine_responder(&packet, conn),
                    (_, Err(e)) => NotHandled(e),
                }
            }
            Err(PacketParseError::Io(error)) => Failure(error),
            Err(e) => NotHandled(ConnectError::ParseFailed(e)),
        }
    }

    pub fn handle_tick(&mut self, now: Instant) -> ConnectionResult {
        self.last_send = Some(now);
        SendPacket(self.last_packet.clone())
    }
}
