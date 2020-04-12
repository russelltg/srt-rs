use std::cmp;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use failure::Error;
use futures::{select, FutureExt, Sink, SinkExt, Stream};
use log::warn;
use tokio::time::interval;

use crate::packet::{ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SocketType};
use crate::protocol::{handshake::Handshake, TimeStamp};
use crate::util::get_packet;
use crate::{
    Connection, ConnectionSettings, ControlPacket, DataPacket, Packet, SeqNumber, SocketID,
};

use RendezvousError::*;
use RendezvousState::*;

pub struct Rendezvous {
    config: RendezvousConfiguration,
    state: RendezvousState,
    seq_num: SeqNumber,
}

pub struct RendezvousConfiguration {
    pub local_socket_id: SocketID,
    pub local_addr: IpAddr,
    pub remote_public: SocketAddr,
    pub tsbpd_latency: Duration,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RendezvousState {
    Negotiating,
    Connected(ConnectionSettings, Option<ControlTypes>),
}

impl Rendezvous {
    pub fn new(config: RendezvousConfiguration) -> Self {
        Self {
            config,
            state: Negotiating,
            seq_num: rand::random(),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum RendezvousError {
    //#[error("Expected Control packet, expected: {0} found: {1}")]
    ControlExpected(DataPacket),
    //#[error("Expected Handshake packet, expected: {0} found: {1}")]
    // warn!("Received non-handshake packet when negotiating rendezvous");
    HandshakeExpected(ControlTypes),
    // #[error("Expected Rendezvous packet, found: {0}")]
    // warn!("Received induction handshake while initiating a rendezvous connection. Maybe you tried to pair connect with rendezvous?");
    RendezvousExpected(HandshakeControlInfo),
    // warn!("Received control packet from unrecognized location: {}", from_addr );
    UnrecognizedHost(SocketAddr, ControlPacket),
}

pub type RendezvousResult = Result<Option<(ControlPacket, SocketAddr)>, RendezvousError>;

impl Rendezvous {
    fn send(&self, packet: ControlPacket) -> RendezvousResult {
        Ok(Some((packet, self.config.remote_public)))
    }

    fn set_state_connected(
        &mut self,
        info: &HandshakeControlInfo,
        control_type: Option<ControlTypes>,
    ) {
        let config = &self.config;
        self.state = Connected(
            ConnectionSettings {
                remote: config.remote_public,
                max_flow_size: info.max_flow_size,
                max_packet_size: info.max_packet_size,
                init_seq_num: info.init_seq_num,
                socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
                local_sockid: config.local_socket_id,
                remote_sockid: info.socket_id,
                tsbpd_latency: config.tsbpd_latency, // TODO: needs to be send in the handshakes
            },
            control_type,
        );
    }

    fn send_handwave(&mut self) -> RendezvousResult {
        let config = &self.config;
        self.send(ControlPacket {
            timestamp: TimeStamp::from_micros(0), // TODO: is this right?
            dest_sockid: SocketID(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: self.seq_num,
                max_packet_size: 1500, // TODO: take as a parameter
                max_flow_size: 8192,   // TODO: take as a parameter
                socket_id: config.local_socket_id,
                shake_type: ShakeType::Waveahand, // as per the spec, the first packet is waveahand
                peer_addr: config.local_addr,
                syn_cookie: 0,
                info: HandshakeVSInfo::V4(SocketType::Datagram),
            }),
        })
    }

    fn wait_for_negotiation(&mut self, info: HandshakeControlInfo) -> RendezvousResult {
        let config = &self.config;
        self.seq_num = cmp::max(info.init_seq_num, self.seq_num);

        match info.shake_type {
            ShakeType::Waveahand => {
                self.send(ControlPacket {
                    dest_sockid: info.socket_id,
                    timestamp: TimeStamp::from_micros(0), // TODO: deal with timestamp
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Conclusion,
                        socket_id: config.local_socket_id,
                        peer_addr: config.local_addr,
                        init_seq_num: self.seq_num,
                        ..info
                    }),
                })
            }
            ShakeType::Conclusion => {
                // connection is created, send Agreement back
                // TODO: if this packet gets dropped, this connection will never init. This is a pretty big bug.

                let packet = ControlPacket {
                    dest_sockid: info.socket_id,
                    timestamp: TimeStamp::from_micros(0), // TODO: deal with timestamp,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Agreement,
                        socket_id: config.local_socket_id,
                        peer_addr: config.local_addr,
                        ..info.clone()
                    }),
                };

                self.set_state_connected(&info, Some(packet.control_type.clone()));

                self.send(packet)
            }
            ShakeType::Agreement => {
                self.set_state_connected(&info, None);

                Ok(None)
            }
            ShakeType::Induction => Err(RendezvousError::RendezvousExpected(info.clone())),
        }
    }

    pub fn handle_packet(&mut self, next: (Packet, SocketAddr)) -> RendezvousResult {
        match next {
            (Packet::Control(control), from) if from == self.config.remote_public => {
                match control.control_type {
                    ControlTypes::Handshake(info) => self.wait_for_negotiation(info),
                    control_type => Err(HandshakeExpected(control_type)),
                }
            }
            (Packet::Control(control), from) => Err(UnrecognizedHost(from, control)),
            (Packet::Data(data), _) => Err(ControlExpected(data)),
        }
    }

    pub fn handle_tick(&mut self, _now: Instant) -> RendezvousResult {
        match &self.state {
            Negotiating => self.send_handwave(),
            Connected(_, _) => Ok(None),
        }
    }
}

pub async fn rendezvous<T>(
    sock: &mut T,
    local_socket_id: SocketID,
    local_addr: IpAddr,
    remote_public: SocketAddr,
    tsbpd_latency: Duration,
) -> Result<Connection, Error>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
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

        match result {
            Ok(Some((packet, address))) => {
                sock.send((Packet::Control(packet), address)).await?;
            }
            Err(e) => {
                warn!("{:?}", e);
            }
            _ => {}
        }

        if let Connected(settings, control_type) = rendezvous.state {
            return Ok(Connection {
                settings,
                handshake: Handshake::Rendezvous(control_type),
            });
        }
    }
}
