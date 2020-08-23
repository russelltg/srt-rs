use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::packet::*;
use crate::protocol::time::TimeStamp;
use crate::{ConnectionSettings, SocketID};

use super::{
    hsv5::{start_hsv5_initiation, StartedInitiator},
    ConnInitSettings, ConnectError,
};
use ConnectError::*;
use ConnectState::*;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ConnectState {
    Configured,
    /// keep induction packet around for retransmit
    InductionResponseWait(Packet),
    /// keep conclusion packet around for retransmit
    ConclusionResponseWait(Packet, StartedInitiator),
    Connected(ConnectionSettings),
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
}

pub type ConnectResult = Result<Option<(Packet, SocketAddr)>, ConnectError>;

impl Connect {
    pub fn new(remote: SocketAddr, local_addr: IpAddr, init_settings: ConnInitSettings) -> Self {
        Connect {
            remote,
            local_addr,
            init_settings,
            state: ConnectState::new(),
        }
    }
    fn on_start(&mut self) -> ConnectResult {
        let packet = Packet::Control(ControlPacket {
            dest_sockid: SocketID(0),
            timestamp: TimeStamp::from_u32(0), // TODO: this is not zero in the reference implementation
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
        Ok(Some((packet, self.remote)))
    }

    pub fn wait_for_induction(
        &mut self,
        from: SocketAddr,
        timestamp: TimeStamp,
        info: HandshakeControlInfo,
    ) -> ConnectResult {
        match (info.shake_type, &info.info, from) {
            (ShakeType::Induction, HandshakeVSInfo::V5 { .. }, from) if from == self.remote => {
                let (hsv5, cm) = start_hsv5_initiation(self.init_settings.clone())?;

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
                Ok(Some((packet, from)))
            }
            (ShakeType::Induction, HandshakeVSInfo::V5 { .. }, from) => {
                Err(UnexpectedHost(self.remote, from))
            }
            (ShakeType::Induction, version, _) => {
                Err(UnsupportedProtocolVersion(version.version()))
            }
            (_, _, _) => Err(InductionExpected(info)),
        }
    }

    fn wait_for_conclusion(
        &mut self,
        from: SocketAddr,
        info: HandshakeControlInfo,
        initiator: StartedInitiator,
    ) -> ConnectResult {
        match (info.shake_type, info.info.version(), from) {
            (ShakeType::Conclusion, 5, from) if from == self.remote => {
                let settings = initiator.finish_hsv5_initiation(&info, from)?;

                self.state = Connected(settings);

                // TODO: no handshake retransmit packet needed? is this right? Needs testing.

                Ok(None)
            }
            (ShakeType::Conclusion, 5, from) => Err(UnexpectedHost(self.remote, from)),
            (ShakeType::Conclusion, version, _) => Err(UnsupportedProtocolVersion(version)),
            (ShakeType::Induction, _, _) => Ok(None),
            (_, _, _) => Err(ConclusionExpected(info)),
        }
    }

    pub fn handle_packet(&mut self, next: (Packet, SocketAddr)) -> ConnectResult {
        let (packet, from) = next;
        match (self.state.clone(), packet) {
            (InductionResponseWait(_), Packet::Control(control)) => match control.control_type {
                ControlTypes::Handshake(shake) => {
                    self.wait_for_induction(from, control.timestamp, shake)
                }
                control_type => Err(HandshakeExpected(control_type)),
            },
            (ConclusionResponseWait(_, cm), Packet::Control(control)) => match control.control_type
            {
                ControlTypes::Handshake(shake) => self.wait_for_conclusion(from, shake, cm),
                control_type => Err(HandshakeExpected(control_type)),
            },
            (_, Packet::Data(data)) => Err(ControlExpected(data)),
            (_, _) => Ok(None),
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> ConnectResult {
        match &self.state {
            Configured => self.on_start(),
            InductionResponseWait(request_packet) => {
                Ok(Some((request_packet.clone(), self.remote)))
            }
            ConclusionResponseWait(request_packet, _) => {
                Ok(Some((request_packet.clone(), self.remote)))
            }
            _ => Ok(None),
        }
    }

    pub fn state(&self) -> &ConnectState {
        &self.state
    }
}
