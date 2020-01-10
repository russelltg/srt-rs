use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use failure::Error;
use futures::{select, FutureExt, Sink, SinkExt, Stream};
use tokio::time::interval;
use tokio::time::Instant;

use crate::packet::{ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SocketType};
use crate::util::get_packet;
use crate::{
    Connection, ConnectionSettings, ControlPacket, DataPacket, Packet, SeqNumber, SocketID,
};

use std::cmp;
use RendezvousError::*;
use RendezvousState::*;

pub struct Rendezvous(RendezvousConfiguration, RendezvousState, SeqNumber);

pub struct RendezvousConfiguration {
    local_socket_id: SocketID,
    local_addr: IpAddr,
    remote_public: SocketAddr,
    tsbpd_latency: Duration,
}

#[derive(Clone)]
pub enum RendezvousState {
    Negotiating,
    Connected(ConnectionSettings, Option<ControlPacket>),
}

impl Rendezvous {
    pub fn new(config: RendezvousConfiguration) -> Self {
        Self(config, Negotiating, rand::random())
    }
}

#[derive(Debug)]
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
        Ok(Some((packet, self.0.remote_public)))
    }

    fn set_state_connected(&mut self, info: &HandshakeControlInfo, packet: Option<ControlPacket>) {
        eprintln!("Rendezvous CONNECTED!!");

        self.1 = Connected(
            ConnectionSettings {
                remote: self.0.remote_public,
                max_flow_size: info.max_flow_size,
                max_packet_size: info.max_packet_size,
                init_seq_num: info.init_seq_num,
                socket_start_time: Instant::now().into_std(), // restamp the socket start time, so TSBPD works correctly
                local_sockid: self.0.local_socket_id,
                remote_sockid: info.socket_id,
                tsbpd_latency: self.0.tsbpd_latency, // TODO: needs to be send in the handshakes
            },
            packet,
        );
    }

    fn send_handwave(&mut self) -> RendezvousResult {
        let config = &self.0;
        self.send(ControlPacket {
            timestamp: 0, // TODO: is this right?
            dest_sockid: SocketID(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: self.2,
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
        let config = &self.0;
        self.2 = cmp::max(info.init_seq_num, self.2);

        match info.shake_type {
            ShakeType::Waveahand => {
                self.send(ControlPacket {
                    dest_sockid: info.socket_id,
                    timestamp: 0, // TODO: deal with timestamp
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Conclusion,
                        socket_id: config.local_socket_id,
                        peer_addr: config.local_addr,
                        init_seq_num: self.2,
                        ..info
                    }),
                })
            }
            ShakeType::Conclusion => {
                // connection is created, send Agreement back
                // TODO: if this packet gets dropped, this connection will never init. This is a pretty big bug.

                let packet = ControlPacket {
                    dest_sockid: info.socket_id,
                    timestamp: 0, // TODO: deal with timestamp,
                    control_type: ControlTypes::Handshake(HandshakeControlInfo {
                        shake_type: ShakeType::Agreement,
                        socket_id: config.local_socket_id,
                        peer_addr: config.local_addr,
                        ..info.clone()
                    }),
                };

                self.set_state_connected(&info, Some(packet.clone()));

                self.send(packet)
            }
            ShakeType::Agreement => {
                self.set_state_connected(&info, None);

                Ok(None)
            }
            ShakeType::Induction => Err(RendezvousError::RendezvousExpected(info.clone())),
        }
    }

    pub fn next_packet(&mut self, next: (Packet, SocketAddr)) -> RendezvousResult {
        match next {
            (Packet::Control(control), from) if from == self.0.remote_public => {
                match control.control_type {
                    ControlTypes::Handshake(info) => self.wait_for_negotiation(info),
                    control_type => Err(HandshakeExpected(control_type)),
                }
            }
            (Packet::Control(control), from) => Err(UnrecognizedHost(from, control)),
            (Packet::Data(data), _) => Err(ControlExpected(data)),
        }
    }

    pub fn next_tick(&mut self, _now: Instant) -> RendezvousResult {
        match &self.1 {
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
            now = tick_interval.tick().fuse() => rendezvous.next_tick(now),
            packet = get_packet(sock).fuse() => rendezvous.next_packet(packet?),
        };

        match result {
            Ok(Some((packet, address))) => {
                sock.send((Packet::Control(packet), address)).await?;
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
            _ => {}
        }

        match rendezvous.1 {
            Connected(settings, packet) => {
                return Ok(Connection {
                    settings,
                    hs_returner: Box::new(move |pack| {
                        if let Packet::Control(ControlPacket {
                            control_type: ControlTypes::Handshake(info),
                            ..
                        }) = pack
                        {
                            match info.shake_type {
                                ShakeType::Conclusion => {
                                    packet.as_ref().map(|p| Packet::Control(p.clone()))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }),
                });
            }
            _ => {}
        }
    }
}