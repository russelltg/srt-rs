use std::{
    cmp::{max, Ordering},
    fmt, io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::cookie::gen_cookie;

use futures::{select, FutureExt, Sink, SinkExt, Stream};
use log::{debug, trace, warn};
use tokio::time::interval;

use crate::packet::{
    ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SrtControlPacket, SrtHandshake,
    SrtShakeFlags,
};
use crate::protocol::{handshake::Handshake, TimeStamp};
use crate::util::get_packet;
use crate::{
    Connection, ConnectionSettings, ControlPacket, DataPacket, Packet, PacketParseError, SeqNumber,
    SocketID, SrtVersion,
};

use RendezvousError::*;
use RendezvousState::*;

pub struct Rendezvous {
    config: RendezvousConfiguration,
    state: RendezvousState,
    seq_num: SeqNumber,
    cookie: i32,
    last_packet: (ControlPacket, SocketAddr),
    connection: Option<Connection>,
}

pub struct RendezvousConfiguration {
    pub local_socket_id: SocketID,
    pub local_addr: SocketAddr,
    pub remote_public: SocketAddr,
    pub tsbpd_latency: Duration,
}

// see haivision/srt/docs/handshake.md for documentation

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum RendezvousState {
    Waving,
    Attention(RendezvousRole),
    InitiatedResponder(HandshakeControlInfo, SrtHandshake), // responders always have the handshake when they transition to initiated
    InitiatedInitiator,
    FineResponder(HandshakeControlInfo, SrtHandshake),
    FineInitiator,
}

impl Rendezvous {
    pub fn new(config: RendezvousConfiguration) -> Self {
        let cookie = gen_cookie(&config.local_addr);
        let seq_num = rand::random();
        let last_packet = (
            ControlPacket {
                dest_sockid: SocketID(0),
                timestamp: TimeStamp::from_micros(0),
                control_type: ControlTypes::Handshake(config.gen_packet(
                    seq_num,
                    ShakeType::Waveahand,
                    cookie,
                    Rendezvous::empty_flags(),
                )),
            },
            config.remote_public,
        );

        Self {
            config,
            state: Waving,
            seq_num,
            cookie,
            last_packet,
            connection: None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum RendezvousError {
    ControlExpected(DataPacket),
    HandshakeExpected(ControlTypes),
    RendezvousExpected(HandshakeControlInfo),
    UnrecognizedHost(SocketAddr, Packet),
    HSV5Expected(HandshakeControlInfo),
    CookiesMatched(i32),
    ExpectedHSReq,
    ExpectedHSResp,
    ExpectedExtFlags,
    ExpectedNoExtFlags,
}

impl fmt::Display for RendezvousError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ControlExpected(pack) => write!(f, "Expected Control packet, found {:?}", pack),
            HandshakeExpected(got) => write!(f, "Expected Handshake packet, found: {:?}", got),
            RendezvousExpected(got) => write!(f, "Expected rendezvous packet, got {:?}", got),
            UnrecognizedHost(from, packet) => write!(
                f,
                "Received control packet {:?} from unrecognized location: {}",
                packet, from
            ),
            HSV5Expected(got) => write!(
                f,
                "Expected hsv5 packet from rendezvouos peer, got {:?}",
                got
            ),
            CookiesMatched(cookie) => write!(
                f,
                "Cookies matched, waiting for a new cookie to resolve contest. Cookie: {}",
                cookie
            ),
            ExpectedHSReq => write!(
                f,
                "Responder got handshake flags, but expected request, not response"
            ),
            ExpectedHSResp => write!(
                f,
                "Initiator got handshake flags, but expected response, not request"
            ),
            ExpectedExtFlags => write!(f, "Responder expected handshake flags, but got none"),
            ExpectedNoExtFlags => {
                write!(f, "Initiator did not expect handshake flags, but got some")
            }
        }
    }
}

pub type RendezvousResult = Result<Option<(ControlPacket, SocketAddr)>, RendezvousError>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum RendezvousRole {
    Initiator,
    Responder,
}
use RendezvousRole::*;

fn get_handshake(packet: &Packet) -> Result<&HandshakeControlInfo, RendezvousError> {
    match packet {
        Packet::Control(ControlPacket {
            control_type: ControlTypes::Handshake(info),
            ..
        }) => Ok(info),
        Packet::Control(ControlPacket { control_type, .. }) => {
            Err(RendezvousError::HandshakeExpected(control_type.clone()))
        }
        Packet::Data(data) => Err(ControlExpected(data.clone())),
    }
}

fn extract_ext_info(
    info: &HandshakeControlInfo,
) -> Result<Option<&SrtControlPacket>, RendezvousError> {
    match &info.info {
        HandshakeVSInfo::V5 { ext_hs, .. } => Ok(ext_hs.as_ref()),
        _ => Err(HSV5Expected(info.clone())),
    }
}

impl Rendezvous {
    fn empty_flags() -> HandshakeVSInfo {
        HandshakeVSInfo::V5 {
            crypto_size: 0,
            ext_config: None,
            ext_hs: None,
            ext_km: None,
        }
    }

    fn gen_flags(&self, role: RendezvousRole) -> HandshakeVSInfo {
        let shake = SrtHandshake {
            version: SrtVersion::CURRENT,
            flags: SrtShakeFlags::TSBPDSND | SrtShakeFlags::TSBPDRCV,
            peer_latency: Duration::from_secs(0),
            latency: self.config.tsbpd_latency,
        };
        HandshakeVSInfo::V5 {
            crypto_size: 0,
            ext_hs: Some(match role {
                Responder => SrtControlPacket::HandshakeResponse(shake),
                Initiator => SrtControlPacket::HandshakeRequest(shake),
            }),
            ext_km: None,
            ext_config: None,
        }
    }

    fn gen_packet(&self, shake_type: ShakeType, info: HandshakeVSInfo) -> HandshakeControlInfo {
        self.config
            .gen_packet(self.seq_num, shake_type, self.cookie, info)
    }

    fn send(&mut self, dest_sockid: SocketID, packet: HandshakeControlInfo) -> RendezvousResult {
        let pack_pair = (
            ControlPacket {
                timestamp: TimeStamp::from_micros(0),
                dest_sockid,
                control_type: ControlTypes::Handshake(packet),
            },
            self.config.remote_public,
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

    fn set_connected(
        &mut self,
        info: &HandshakeControlInfo,
        srt_exts: &SrtHandshake,
        resp: Option<ControlTypes>,
    ) {
        self.connection = Some(Connection {
            settings: ConnectionSettings {
                remote: self.config.remote_public,
                remote_sockid: info.socket_id,
                local_sockid: self.config.local_socket_id,
                socket_start_time: Instant::now(),
                init_send_seq_num: self.seq_num,
                init_recv_seq_num: info.init_seq_num,
                max_packet_size: info.max_packet_size,
                max_flow_size: info.max_flow_size,
                tsbpd_latency: max(srt_exts.latency, self.config.tsbpd_latency),
            },
            handshake: Handshake::Rendezvous(resp),
        });
    }

    fn handle_waving(&mut self, info: &HandshakeControlInfo) -> RendezvousResult {
        assert!(matches!(self.state, Waving));

        // NOTE: the cookie comparsion behavior is not correctly documented. See haivision/srt#1267
        let role = match self.cookie.wrapping_sub(info.syn_cookie).cmp(&0) {
            Ordering::Greater => Initiator,
            Ordering::Less => Responder,
            Ordering::Equal => return Err(RendezvousError::CookiesMatched(self.cookie)),
        };

        match info.shake_type {
            ShakeType::Waveahand => {
                self.state = Attention(role);
                debug!(
                    "Rendezvous {:?} transitioning from Wavahand to {:?}",
                    self.config.local_socket_id, self.state
                );
                self.send_conclusion(
                    info.socket_id,
                    match role {
                        Initiator => self.gen_flags(role),
                        Responder => Rendezvous::empty_flags(),
                    },
                )
            }
            ShakeType::Conclusion => {
                self.state = match (role, extract_ext_info(info)?) {
                    (Responder, Some(SrtControlPacket::HandshakeRequest(hsreq))) => {
                        FineResponder(info.clone(), *hsreq)
                    }
                    (Initiator, None) => FineInitiator,
                    (Responder, Some(_)) => {
                        return Err(RendezvousError::ExpectedHSReq);
                    }
                    (Initiator, Some(_)) => return Err(RendezvousError::ExpectedNoExtFlags),
                    (Responder, None) => return Err(RendezvousError::ExpectedExtFlags),
                };
                debug!(
                    "Rendezvous {:?} transitioning from Wavahand to {:?}",
                    self.config.local_socket_id, self.state
                );
                self.send_conclusion(info.socket_id, self.gen_flags(role))
            }
            ShakeType::Agreement => Ok(None),
            ShakeType::Induction => Err(RendezvousError::RendezvousExpected(info.clone())),
        }
    }

    fn handle_attention(
        &mut self,
        role: RendezvousRole,
        info: &HandshakeControlInfo,
    ) -> RendezvousResult {
        match (info.shake_type, role) {
            (ShakeType::Conclusion, Initiator) => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(request)) => {
                    let agreement =
                        self.gen_packet(ShakeType::Agreement, Rendezvous::empty_flags());
                    self.set_connected(
                        info,
                        request,
                        Some(ControlTypes::Handshake(agreement.clone())),
                    );
                    self.send(info.socket_id, agreement)
                }
                Some(_) => Err(RendezvousError::ExpectedHSResp),
                None => {
                    debug!(
                        "Rendezvous {:?} transitioning from {:?} to {:?}",
                        self.config.local_socket_id, self.state, InitiatedInitiator,
                    );
                    self.state = InitiatedInitiator;
                    self.send_conclusion(info.socket_id, self.gen_flags(role))
                }
            },
            (ShakeType::Conclusion, Responder) => {
                let request = match extract_ext_info(info)? {
                    Some(SrtControlPacket::HandshakeRequest(request)) => request,
                    Some(_) => return Err(ExpectedHSReq),
                    None => return Err(ExpectedExtFlags),
                };
                debug!(
                    "Rendezvous {:?} transitioning from {:?} to {:?}",
                    self.config.local_socket_id,
                    self.state,
                    InitiatedResponder(info.clone(), *request),
                );
                self.state = InitiatedResponder(info.clone(), *request);
                self.send_conclusion(info.socket_id, self.gen_flags(Responder))
            }
            _ => Ok(None), // todo: errors
        }
    }

    fn handle_fine_initiator(&mut self, info: &HandshakeControlInfo) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(response)) => {
                    let agreement =
                        self.gen_packet(ShakeType::Agreement, self.gen_flags(Initiator));

                    self.set_connected(
                        info,
                        response,
                        Some(ControlTypes::Handshake(agreement.clone())),
                    );

                    self.send(info.socket_id, agreement)
                }
                Some(_) => Err(RendezvousError::ExpectedHSResp),
                None => Err(RendezvousError::ExpectedExtFlags),
            },
            _ => Ok(None), // real errors here
        }
    }

    fn handle_fine_responder(
        &mut self,
        prev_info: &HandshakeControlInfo,
        shake: &SrtHandshake,
        packet: &Packet,
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
            }) => self.set_connected(prev_info, shake, None),
            _ => {}
        }
        Ok(None)
    }

    fn handle_initiated_initiator(&mut self, info: &HandshakeControlInfo) -> RendezvousResult {
        match info.shake_type {
            ShakeType::Conclusion => match extract_ext_info(info)? {
                Some(SrtControlPacket::HandshakeResponse(srt_shake)) => {
                    self.set_connected(info, srt_shake, None);
                    self.send_agreement(info.socket_id, Rendezvous::empty_flags())
                }
                Some(_) => Err(RendezvousError::ExpectedHSResp),
                None => Err(RendezvousError::ExpectedExtFlags), // spec says stay in this state
            },
            _ => Ok(None), // real errors here
        }
    }

    fn handle_initiated_responder(
        &mut self,
        shake: &SrtHandshake,
        last_info: &HandshakeControlInfo,
        packet: &Packet,
    ) -> RendezvousResult {
        // if the shake still has flags, respond with flags and don't finish.
        if let Ok(info) = get_handshake(packet) {
            match (info.shake_type, extract_ext_info(info)?) {
                (ShakeType::Conclusion, Some(SrtControlPacket::HandshakeRequest(_))) => {
                    return Ok(None);
                }
                (ShakeType::Conclusion, Some(_)) => return Err(ExpectedHSReq),
                _ => {}
            }
        }
        self.set_connected(last_info, shake, None);
        self.send_agreement(last_info.socket_id, Rendezvous::empty_flags())
    }

    pub fn handle_packet(&mut self, (packet, from): (Packet, SocketAddr)) -> RendezvousResult {
        if from != self.config.remote_public {
            return Err(UnrecognizedHost(from, packet));
        }

        let hs = get_handshake(&packet);
        match self.state.clone() {
            Waving => self.handle_waving(hs?),
            Attention(role) => self.handle_attention(role, hs?),
            InitiatedInitiator => self.handle_initiated_initiator(hs?),
            InitiatedResponder(info, request) => {
                self.handle_initiated_responder(&request, &info, &packet)
            }
            FineInitiator => self.handle_fine_initiator(hs?),
            FineResponder(prev_info, request) => {
                self.handle_fine_responder(&prev_info, &request, &packet)
            }
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> RendezvousResult {
        Ok(Some(self.last_packet.clone()))
    }
}

impl RendezvousConfiguration {
    fn gen_packet(
        &self,
        init_seq_num: SeqNumber,
        shake_type: ShakeType,
        syn_cookie: i32,
        info: HandshakeVSInfo,
    ) -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num,
            max_packet_size: 1500, // TODO: take as a parameter
            max_flow_size: 8192,   // TODO: take as a parameter
            socket_id: self.local_socket_id,
            shake_type,
            peer_addr: self.local_addr.ip(),
            syn_cookie,
            info,
        }
    }
}

pub async fn rendezvous<T>(
    sock: &mut T,
    local_socket_id: SocketID,
    local_addr: SocketAddr,
    remote_public: SocketAddr,
    tsbpd_latency: Duration,
) -> Result<Connection, io::Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), PacketParseError>>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Unpin,
{
    let configuration = RendezvousConfiguration {
        local_socket_id,
        local_addr,
        remote_public,
        tsbpd_latency,
    };

    let mut rendezvous = Rendezvous::new(configuration);

    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => rendezvous.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => rendezvous.handle_packet(packet?),
        };

        trace!("Ticking {:?} {:?}", local_socket_id, rendezvous.state);

        match result {
            Ok(Some((packet, address))) => {
                sock.send((Packet::Control(packet), address)).await?;
            }
            Err(e) => {
                warn!("rendezvous {:?} error: {}", local_socket_id, e);
            }
            _ => {}
        }

        if let Some(connection) = rendezvous.connection {
            return Ok(connection);
        }
    }
}
