use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use failure::Error;
use futures::prelude::*;
use futures::select;
use log::warn;
use tokio::time::interval;

use crate::packet::*;
use crate::protocol::handshake::Handshake;
use crate::util::get_packet;
use crate::{Connection, ConnectionSettings, SeqNumber, SocketID, SrtVersion};

use ConnectError::*;
use ConnectState::*;

pub struct ConnectConfiguration {
    pub remote: SocketAddr,
    pub local_sockid: SocketID,
    pub local_addr: IpAddr,
    pub tsbpd_latency: Duration,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ConnectState {
    /// initial sequence number
    Configured(SeqNumber),
    /// keep induction packet around for retransmit
    InductionResponseWait(Packet),
    /// keep conclusion packet around for retransmit
    ConclusionResponseWait(Packet),
    Connected(ConnectionSettings),
}

impl Default for ConnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectState {
    pub fn new() -> ConnectState {
        Configured(rand::random())
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ConnectError {
    //#[error("Expected Control packet, expected: {0} found: {1}")]
    ControlExpected(ShakeType, DataPacket),
    //#[error("Expected Handshake packet, expected: {0} found: {1}")]
    HandshakeExpected(ShakeType, ControlTypes),
    //#[error("Expected Induction (1) packet, found: {0}")]
    InductionExpected(HandshakeControlInfo),
    //#[error("Expected packets from different host, expected: {0} found: {1}")]
    UnexpectedHost(SocketAddr, SocketAddr),
    //#[error("Expected Conclusion (-1) packet, found: {0}")]
    ConclusionExpected(HandshakeControlInfo),
    //#[error("Unsupported protocol version, expected: v5 found v{0}")]
    UnsupportedProtocolVersion(u32),
    // TODO: why don't we validate the cookie on responses
    //#[error("Received invalid cookie handshake from [address], expected: {0} found {1}")]
    //InvalidHandshakeCookie(i32, i32),
    // TODO: why don't we validate we have an SRT response
    //#[error("Expected SRT handshake request in conclusion handshake, found {0}")]
    //SrtHandshakeExpected(HandshakeControlInfo),
}

pub struct Connect {
    config: ConnectConfiguration,
    state: ConnectState,
}

pub type ConnectResult = Result<Option<(Packet, SocketAddr)>, ConnectError>;

impl Connect {
    fn on_start(&mut self, init_seq_num: SeqNumber) -> ConnectResult {
        let config = &self.config;
        let packet = Packet::Control(ControlPacket {
            dest_sockid: SocketID(0),
            timestamp: 0, // TODO: this is not zero in the reference implementation
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num,
                max_packet_size: 1500, // TODO: take as a parameter
                max_flow_size: 8192,   // TODO: take as a parameter
                socket_id: config.local_sockid,
                shake_type: ShakeType::Induction,
                peer_addr: config.local_addr,
                syn_cookie: 0,
                info: HandshakeVSInfo::V4(SocketType::Datagram),
            }),
        });
        self.state = InductionResponseWait(packet.clone());
        Ok(Some((packet, config.remote)))
    }

    pub fn wait_for_induction(
        &mut self,
        from: SocketAddr,
        timestamp: i32,
        info: HandshakeControlInfo,
    ) -> ConnectResult {
        let config = &self.config;
        match (info.shake_type, info.info.version(), from) {
            (ShakeType::Induction, 5, from) if from == config.remote => {
                // send back a packet with the same syn cookie
                let packet = Packet::Control(ControlPacket {
                    timestamp,
                    dest_sockid: SocketID(0),
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Conclusion,
                        socket_id: config.local_sockid,
                        info: HandshakeVSInfo::V5 {
                            crypto_size: 0, // TODO: implement
                            ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                                version: SrtVersion::CURRENT,
                                // TODO: this is hyper bad, don't blindly set send flag
                                // if you don't pass TSBPDRCV, it doens't set the latency correctly for some reason. Requires more research
                                peer_latency: Duration::from_secs(0), // TODO: research
                                flags: SrtShakeFlags::TSBPDSND | SrtShakeFlags::TSBPDRCV, // TODO: the reference implementation sets a lot more of these, research
                                latency: config.tsbpd_latency,
                            })),
                            ext_km: None,
                            // ext_km: self.crypto.as_mut().map(|manager| {
                            //     SrtControlPacket::KeyManagerRequest(SrtKeyMessage {
                            //         pt: 2,       // TODO: what is this
                            //         sign: 8_233, // TODO: again
                            //         keki: 0,
                            //         cipher: CipherType::CTR,
                            //         auth: 0,
                            //         se: 2,
                            //         salt: Vec::from(manager.salt()),
                            //         even_key: Some(manager.wrap_key().unwrap()),
                            //         odd_key: None,
                            //         wrap_data: [0; 8],
                            //     })
                            // }),
                            ext_config: None,
                        },
                        ..info
                    }),
                });
                self.state = ConclusionResponseWait(packet.clone());
                Ok(Some((packet, from)))
            }
            (ShakeType::Induction, 5, from) => Err(UnexpectedHost(config.remote, from)),
            (ShakeType::Induction, version, _) => Err(UnsupportedProtocolVersion(version)),
            (_, _, _) => Err(InductionExpected(info)),
        }
    }

    fn wait_for_conclusion(
        &mut self,
        from: SocketAddr,
        info: HandshakeControlInfo,
    ) -> ConnectResult {
        let config = &self.config;
        match (info.shake_type, info.info.version(), from) {
            (ShakeType::Conclusion, 5, from) if from == config.remote => {
                let latency = match info.info {
                    HandshakeVSInfo::V5 {
                        ext_hs: Some(SrtControlPacket::HandshakeResponse(hs)),
                        ..
                    } => hs.latency,
                    _ => {
                        warn!("Did not get SRT handhsake in conclusion handshake packet, using latency from connector's end");
                        config.tsbpd_latency
                    }
                };

                self.state = Connected(ConnectionSettings {
                    remote: config.remote,
                    max_flow_size: info.max_flow_size,
                    max_packet_size: info.max_packet_size,
                    init_seq_num: info.init_seq_num,
                    // restamp the socket start time, so TSBPD works correctly.
                    // TODO: technically it would be 1 rtt off....
                    socket_start_time: Instant::now(),
                    local_sockid: config.local_sockid,
                    remote_sockid: info.socket_id,
                    tsbpd_latency: latency,
                });
                // TODO: no handshake retransmit packet needed? is this right? Needs testing.

                Ok(None)
            }
            (ShakeType::Conclusion, 5, from) => Err(UnexpectedHost(config.remote, from)),
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
                control_type => Err(HandshakeExpected(ShakeType::Induction, control_type)),
            },
            (ConclusionResponseWait(_), Packet::Control(control)) => match control.control_type {
                ControlTypes::Handshake(shake) => self.wait_for_conclusion(from, shake),
                control_type => Err(HandshakeExpected(ShakeType::Conclusion, control_type)),
            },
            (_, Packet::Data(data)) => Err(ControlExpected(ShakeType::Induction, data)),
            (_, _) => Ok(None),
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> ConnectResult {
        match self.state.clone() {
            Configured(init_seq_num) => self.on_start(init_seq_num),
            InductionResponseWait(request_packet) => Ok(Some((request_packet, self.config.remote))),
            ConclusionResponseWait(request_packet) => {
                Ok(Some((request_packet, self.config.remote)))
            }
            _ => Ok(None),
        }
    }
}

pub async fn connect<T>(
    sock: &mut T,
    remote: SocketAddr,
    local_sockid: SocketID,
    local_addr: IpAddr,
    tsbpd_latency: Duration,
    _crypto: Option<(u8, String)>,
) -> Result<Connection, Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    let mut connect = Connect {
        config: ConnectConfiguration {
            remote,
            local_sockid,
            local_addr,
            tsbpd_latency,
        },
        state: ConnectState::new(),
    };

    let mut tick_interval = interval(Duration::from_millis(100));
    loop {
        let result = select! {
            now = tick_interval.tick().fuse() => connect.handle_tick(now.into()),
            packet = get_packet(sock).fuse() => connect.handle_packet(packet?),
        };

        match result {
            Ok(Some(packet)) => {
                sock.send(packet).await?;
            }
            Err(e) => {
                warn!("{:?}", e);
            }
            _ => {}
        }
        if let Connected(settings) = connect.state.clone() {
            return Ok(Connection {
                settings,
                handshake: Handshake::Connector,
            });
        }
    }
}
