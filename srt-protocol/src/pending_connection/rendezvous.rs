use std::{cmp::Ordering, net::SocketAddr, time::Instant};

use super::{
    cookie::gen_cookie,
    hsv5::{gen_hsv5_response, start_hsv5_initiation, StartedInitiator},
    ConnInitSettings, ConnectError,
};

use log::debug;

use crate::packet::{
    ControlTypes, HSV5Info, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SrtControlPacket,
};
use crate::protocol::{handshake::Handshake, TimeStamp};
use crate::{
    accesscontrol::AllowAllStreamAcceptor, Connection, ConnectionSettings, ControlPacket, Packet,
    SocketID,
};

use ConnectError::*;
use RendezvousState::*;

pub struct Rendezvous {
    init_settings: ConnInitSettings,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    state: RendezvousState,
    cookie: i32,
    last_packet: (ControlPacket, SocketAddr),
    connection: Option<Connection>,
}

// see haivision/srt/docs/handshake.md for documentation

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum RendezvousState {
    Waving,
    AttentionInitiator(HandshakeVSInfo, StartedInitiator),
    AttentionResponder,
    InitiatedResponder(ConnectionSettings), // responders always have the handshake when they transition to initiated
    InitiatedInitiator(StartedInitiator),
    FineResponder(ConnectionSettings),
    FineInitiator(HandshakeVSInfo, StartedInitiator),
}

impl Rendezvous {
    pub fn new(
        local_addr: SocketAddr,
        remote_public: SocketAddr,
        init_settings: ConnInitSettings,
    ) -> Self {
        let cookie = gen_cookie(&local_addr);
        let last_packet = (
            ControlPacket {
                dest_sockid: SocketID(0),
                timestamp: TimeStamp::from_micros(0),
                control_type: ControlTypes::Handshake(HandshakeControlInfo {
                    init_seq_num: init_settings.starting_send_seqnum,
                    max_packet_size: 1500, // TODO: take as a parameter
                    max_flow_size: 8192,   // TODO: take as a parameter
                    socket_id: init_settings.local_sockid,
                    shake_type: ShakeType::Waveahand,
                    peer_addr: local_addr.ip(),
                    syn_cookie: cookie, // TODO: !!
                    info: Rendezvous::empty_flags(),
                }),
            },
            remote_public,
        );

        Self {
            state: Waving,
            cookie,
            last_packet,
            connection: None,
            init_settings,
            local_addr,
            remote_public,
        }
    }

    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }
}

pub type RendezvousResult = Result<Option<(ControlPacket, SocketAddr)>, ConnectError>;

#[derive(Debug, Clone)]
enum RendezvousHSV5 {
    Initiator,
    Responder,
}
use RendezvousHSV5::*;

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
        HandshakeVSInfo::V5(hs) => Ok(hs.ext_hs.as_ref()),
        _ => Err(UnsupportedProtocolVersion(4)),
    }
}

impl Rendezvous {
    fn empty_flags() -> HandshakeVSInfo {
        HandshakeVSInfo::V5(HSV5Info::default())
    }

    fn transition(&mut self, state: RendezvousState) {
        debug!(
            "Rendezvous {:?} transitioning from {:?} to {:?}",
            self.init_settings.local_sockid, self.state, state,
        );
        self.state = state
    }

    fn gen_packet(&self, shake_type: ShakeType, info: HandshakeVSInfo) -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: self.init_settings.starting_send_seqnum,
            max_packet_size: 1500, // TODO: take as a parameter
            max_flow_size: 8192,   // TODO: take as a parameter
            socket_id: self.init_settings.local_sockid,
            shake_type,
            peer_addr: self.local_addr.ip(),
            syn_cookie: self.cookie, // TODO: !!
            info,
        }
    }

    fn send(&mut self, dest_sockid: SocketID, packet: HandshakeControlInfo) -> RendezvousResult {
        let pack_pair = (
            ControlPacket {
                timestamp: TimeStamp::from_micros(0),
                dest_sockid,
                control_type: ControlTypes::Handshake(packet),
            },
            self.remote_public,
        );
        self.last_packet = pack_pair.clone();
        Ok(Some(pack_pair))
    }

    fn send_conclusion(
        &mut self,
        dest_sockid: SocketID,
        info: HandshakeVSInfo,
    ) -> RendezvousResult {
        self.send(dest_sockid, self.gen_packet(ShakeType::Conclusion, info))
    }

    fn send_agreement(&mut self, dest_sockid: SocketID, info: HandshakeVSInfo) -> RendezvousResult {
        self.send(dest_sockid, self.gen_packet(ShakeType::Agreement, info))
    }

    fn set_connected(&mut self, settings: ConnectionSettings, resp: Option<ControlTypes>) {
        self.connection = Some(Connection {
            settings,
            handshake: Handshake::Rendezvous(resp),
        });
    }

    fn handle_waving(&mut self, info: &HandshakeControlInfo) -> RendezvousResult {
        assert!(matches!(self.state, Waving));

        // NOTE: the cookie comparsion behavior is not correctly documented. See haivision/srt#1267
        let role = match self.cookie.wrapping_sub(info.syn_cookie).cmp(&0) {
            Ordering::Greater => Initiator,
            Ordering::Less => Responder,
            Ordering::Equal => return Err(CookiesMatched(self.cookie)),
        };

        match (info.shake_type, role) {
            (ShakeType::Waveahand, Initiator) => {
                let (hsv5, initiator) = start_hsv5_initiation(self.init_settings.clone(), None)?; // NOTE: streamid not supported in rendezvous

                self.transition(AttentionInitiator(hsv5.clone(), initiator));

                self.send_conclusion(info.socket_id, hsv5)
            }
            (ShakeType::Waveahand, Responder) => {
                self.transition(AttentionResponder);
                self.send_conclusion(info.socket_id, Rendezvous::empty_flags())
            }
            (ShakeType::Conclusion, role) => {
                let hsv5_shake = match (&role, extract_ext_info(info)?) {
                    (Responder, Some(SrtControlPacket::HandshakeRequest(_))) => {
                        let (hsv5, connection) = gen_hsv5_response(
                            &mut self.init_settings,
                            info,
                            self.remote_public,
                            &mut AllowAllStreamAcceptor::default(),
                        )?;
                        self.transition(FineResponder(connection));

                        hsv5
                    }
                    (Initiator, None) => {
                        let (hsv5, initiator) =
                            start_hsv5_initiation(self.init_settings.clone(), None)?; // NOTE: streamid not supported in rendezvous
                        self.transition(FineInitiator(hsv5.clone(), initiator));
                        hsv5
                    }
                    (Responder, Some(_)) => {
                        return Err(ExpectedHSReq);
                    }
                    (Initiator, Some(_)) => return Err(ExpectedNoExtFlags),
                    (Responder, None) => return Err(ExpectedExtFlags),
                };
                self.send_conclusion(info.socket_id, hsv5_shake)
            }
            (ShakeType::Agreement, _) => Ok(None),
            (ShakeType::Induction, _) => Err(RendezvousExpected(info.clone())),
            (ShakeType::Rejection(rej), _) => Err(rej.into()),
        }
    }

    fn handle_attention_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        hsv5: HandshakeVSInfo,
        initiator: StartedInitiator,
    ) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(_)) => {
                    let agreement =
                        self.gen_packet(ShakeType::Agreement, Rendezvous::empty_flags());

                    let settings = initiator.finish_hsv5_initiation(info, self.remote_public)?;

                    self.set_connected(settings, Some(ControlTypes::Handshake(agreement.clone())));
                    self.send(info.socket_id, agreement)
                }
                Some(_) => Err(ExpectedHSResp),
                None => {
                    self.transition(InitiatedInitiator(initiator));
                    self.send_conclusion(info.socket_id, hsv5)
                }
            },
            _ => Ok(None), // todo: errors
        }
    }

    fn handle_attention_responder(&mut self, info: &HandshakeControlInfo) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => {
                match extract_ext_info(info)? {
                    Some(SrtControlPacket::HandshakeRequest(_)) => {} // ok, continue
                    Some(_) => return Err(ExpectedHSReq),
                    None => return Err(ExpectedExtFlags),
                };
                let (hsv5, connection) = gen_hsv5_response(
                    &mut self.init_settings,
                    info,
                    self.remote_public,
                    &mut AllowAllStreamAcceptor::default(),
                )?;
                self.transition(InitiatedResponder(connection));

                self.send_conclusion(info.socket_id, hsv5)
            }
            _ => Ok(None),
        }
    }

    fn handle_fine_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        hsv5: HandshakeVSInfo,
        initiator: StartedInitiator,
    ) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(_)) => {
                    let agreement = self.gen_packet(ShakeType::Agreement, hsv5);

                    let settings = initiator.finish_hsv5_initiation(info, self.remote_public)?;
                    self.set_connected(settings, Some(ControlTypes::Handshake(agreement.clone())));

                    self.send(info.socket_id, agreement)
                }
                Some(_) => Err(ExpectedHSResp),
                None => Err(ExpectedExtFlags),
            },
            _ => Ok(None), // real errors here
        }
    }

    fn handle_fine_responder(
        &mut self,
        packet: &Packet,
        connection: ConnectionSettings,
    ) -> RendezvousResult {
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
            }) => self.set_connected(connection, None),
            _ => {}
        }
        Ok(None)
    }

    fn handle_initiated_initiator(
        &mut self,
        info: &HandshakeControlInfo,
        initiator: StartedInitiator,
    ) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(_)) => {
                    let connection = initiator.finish_hsv5_initiation(info, self.remote_public)?;

                    self.set_connected(connection, None);
                    self.send_agreement(info.socket_id, Rendezvous::empty_flags())
                }
                Some(_) => Err(ExpectedHSResp),
                None => Err(ExpectedExtFlags), // spec says stay in this state
            },
            _ => Ok(None), // real errors here
        }
    }

    fn handle_initiated_responder(
        &mut self,
        packet: &Packet,
        connection: ConnectionSettings,
    ) -> RendezvousResult {
        // if the shake still has flags, respond with flags and don't finish.
        if let Ok(info) = get_handshake(packet) {
            match (info.shake_type, extract_ext_info(info)?) {
                (ShakeType::Conclusion, Some(SrtControlPacket::HandshakeRequest(_))) => {
                    return Ok(None); // TODO: this is a pretty roundabout way to do this...just waits for another tick
                }
                (ShakeType::Conclusion, Some(_)) => return Err(ExpectedHSReq),
                _ => {}
            }
        }
        let remote_sockid = connection.remote_sockid;

        self.set_connected(connection, None);
        self.send_agreement(remote_sockid, Rendezvous::empty_flags())
    }

    pub fn handle_packet(&mut self, (packet, from): (Packet, SocketAddr)) -> RendezvousResult {
        if from != self.remote_public {
            return Err(UnexpectedHost(self.remote_public, from));
        }

        let hs = get_handshake(&packet);
        match self.state.clone() {
            Waving => self.handle_waving(hs?),
            AttentionInitiator(hsv5, initiator) => {
                self.handle_attention_initiator(hs?, hsv5, initiator)
            }
            AttentionResponder => self.handle_attention_responder(hs?),
            InitiatedInitiator(initiator) => self.handle_initiated_initiator(hs?, initiator),
            InitiatedResponder(connection) => self.handle_initiated_responder(&packet, connection),
            FineInitiator(hsv5, initiator) => self.handle_fine_initiator(hs?, hsv5, initiator),
            FineResponder(conn) => self.handle_fine_responder(&packet, conn),
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> RendezvousResult {
        Ok(Some(self.last_packet.clone()))
    }
}
