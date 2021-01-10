use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::protocol::{handshake::Handshake, TimeStamp};
use crate::SocketID;
use crate::{packet::*, Connection};

use super::{
    hsv5::{start_hsv5_initiation, StartedInitiator},
    ConnInitSettings, ConnectError, ConnectionResult,
};
use ConnectError::*;
use ConnectState::*;
use ConnectionResult::*;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum ConnectState {
    Configured,
    /// keep induction packet around for retransmit
    InductionResponseWait(Packet),
    /// keep conclusion packet around for retransmit
    ConclusionResponseWait(Packet, StartedInitiator),
}

impl Default for ConnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectState {
    pub fn new() -> ConnectState {
        Configured
    }
}

pub struct Connect {
    remote: SocketAddr,
    local_addr: IpAddr,
    init_settings: ConnInitSettings,
    state: ConnectState,
    streamid: Option<String>,
}

impl Connect {
    pub fn new(
        remote: SocketAddr,
        local_addr: IpAddr,
        init_settings: ConnInitSettings,
        streamid: Option<String>,
    ) -> Self {
        Connect {
            remote,
            local_addr,
            init_settings,
            state: ConnectState::new(),
            streamid,
        }
    }
    fn on_start(&mut self) -> ConnectionResult {
        let packet = Packet::Control(ControlPacket {
            dest_sockid: SocketID(0),
            timestamp: TimeStamp::from_micros(0), // TODO: this is not zero in the reference implementation
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: self.init_settings.starting_send_seqnum,
                max_packet_size: 1500, // TODO: take as a parameter
                max_flow_size: 8192,   // TODO: take as a parameter
                socket_id: self.init_settings.local_sockid,
                shake_type: ShakeType::Induction,
                peer_addr: self.local_addr,
                syn_cookie: 0,
                info: HandshakeVSInfo::V4(SocketType::Datagram),
            }),
        });
        self.state = InductionResponseWait(packet.clone());
        SendPacket((packet, self.remote))
    }

    pub fn wait_for_induction(
        &mut self,
        from: SocketAddr,
        timestamp: TimeStamp,
        info: HandshakeControlInfo,
    ) -> ConnectionResult {
        match (info.shake_type, &info.info, from) {
            (ShakeType::Induction, HandshakeVSInfo::V5 { .. }, from) if from == self.remote => {
                let (hsv5, cm) = match start_hsv5_initiation(
                    self.init_settings.clone(),
                    self.streamid.clone(),
                ) {
                    Ok(hc) => hc,
                    Err(rr) => todo!(), //return Reject(rr),
                };

                // send back a packet with the same syn cookie
                let packet = Packet::Control(ControlPacket {
                    timestamp,
                    dest_sockid: SocketID(0),
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Conclusion,
                        socket_id: self.init_settings.local_sockid,
                        info: hsv5,
                        init_seq_num: self.init_settings.starting_send_seqnum,
                        ..info
                    }),
                });
                self.state = ConclusionResponseWait(packet.clone(), cm);
                SendPacket((packet, from))
            }
            (ShakeType::Induction, HandshakeVSInfo::V5 { .. }, from) => {
                NotHandled(UnexpectedHost(self.remote, from))
            }
            (ShakeType::Induction, version, _) => {
                NotHandled(UnsupportedProtocolVersion(version.version()))
            }
            (_, _, _) => NotHandled(InductionExpected(info)),
        }
    }

    fn wait_for_conclusion(
        &mut self,
        from: SocketAddr,
        info: HandshakeControlInfo,
        initiator: StartedInitiator,
    ) -> ConnectionResult {
        match (info.shake_type, info.info.version(), from) {
            (ShakeType::Conclusion, 5, from) if from == self.remote => {
                let settings = match initiator.finish_hsv5_initiation(&info, from) {
                    Ok(s) => s,
                    Err(rr) => return NotHandled(rr),
                };

                // TODO: no handshake retransmit packet needed? is this right? Needs testing.
                Connected(Connection {
                    settings,
                    handshake: Handshake::Connector,
                })
            }
            (ShakeType::Conclusion, 5, from) => NotHandled(UnexpectedHost(self.remote, from)),
            (ShakeType::Conclusion, version, _) => NotHandled(UnsupportedProtocolVersion(version)),
            (ShakeType::Induction, _, _) => NoAction,
            (_, _, _) => NotHandled(ConclusionExpected(info)),
        }
    }

    pub fn handle_packet(&mut self, next: (Packet, SocketAddr)) -> ConnectionResult {
        let (packet, from) = next;
        match (self.state.clone(), packet) {
            (InductionResponseWait(_), Packet::Control(control)) => match control.control_type {
                ControlTypes::Handshake(shake) => {
                    self.wait_for_induction(from, control.timestamp, shake)
                }
                control_type => NotHandled(HandshakeExpected(control_type)),
            },
            (ConclusionResponseWait(_, cm), Packet::Control(control)) => match control.control_type
            {
                ControlTypes::Handshake(shake) => self.wait_for_conclusion(from, shake, cm),
                control_type => NotHandled(HandshakeExpected(control_type)),
            },
            (_, Packet::Data(data)) => NotHandled(ControlExpected(data)),
            (_, _) => NoAction,
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> ConnectionResult {
        match &self.state {
            Configured => self.on_start(),
            InductionResponseWait(request_packet) => {
                SendPacket((request_packet.clone(), self.remote))
            }
            ConclusionResponseWait(request_packet, _) => {
                SendPacket((request_packet.clone(), self.remote))
            }
        }
    }
}
