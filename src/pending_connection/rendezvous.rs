use std::cmp;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use failure::{bail, Error};
use futures::prelude::*;

use log::warn;

use tokio::timer::Interval;

use crate::connected::Connected;
use crate::packet::{
    ControlPacket, ControlTypes, HandshakeControlInfo, HandshakeVSInfo, ShakeType, SocketType,
};
use crate::{ConnectionSettings, Packet, SeqNumber, SocketID};

pub struct Rendezvous<T> {
    sock: Option<T>,
    local_socket_id: SocketID,
    local_addr: IpAddr,
    remote_public: SocketAddr,
    tsbpd_latency: Duration,

    packet_send_interval: Interval,

    init_seq_num: SeqNumber,
}

impl<T> Rendezvous<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(
        sock: T,
        local_socket_id: SocketID,
        local_addr: IpAddr,
        remote_public: SocketAddr,
        tsbpd_latency: Duration,
    ) -> Rendezvous<T> {
        Rendezvous {
            sock: Some(sock),
            local_socket_id,
            local_addr,
            remote_public,
            tsbpd_latency,
            packet_send_interval: Interval::new_interval(Duration::from_millis(100)), // 10/sec
            init_seq_num: rand::random(),
        }
    }

    fn send_packet(&mut self) -> Result<(), Error> {
        let sock = self.sock.as_mut().unwrap();

        let pack = Packet::Control(ControlPacket {
            timestamp: 0, // TODO: is this right?
            dest_sockid: SocketID(0),
            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                init_seq_num: self.init_seq_num,
                max_packet_size: 1500, // TODO: take as a parameter
                max_flow_size: 8192,   // TODO: take as a parameter
                socket_id: self.local_socket_id,
                shake_type: ShakeType::Waveahand, // as per the spec, the first packet is waveahand
                peer_addr: self.local_addr,
                syn_cookie: 0,
                info: HandshakeVSInfo::V4(SocketType::Datagram),
            }),
        });
        sock.start_send((pack, self.remote_public))?;
        sock.poll_complete()?;
        Ok(())
    }

    fn check_timers(&mut self) -> Result<(), Error> {
        if let Async::Ready(_) = self.packet_send_interval.poll()? {
            self.send_packet()?;
        }

        Ok(())
    }
}

impl<T> Future for Rendezvous<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        self.check_timers()?;

        let sock = self.sock.as_mut().unwrap();
        sock.poll_complete()?;

        // info is the handshake control info for the final handshake packet, to be returned
        // packet is the packet to send if more handshake packets arrive
        let (info, packet) = loop {
            let (packet, from_addr) = match sock.poll() {
                Err(e) => {
                    warn!("Failed to decode packet: {:?}", e);
                    continue;
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(None)) => bail!("Underlying stream unexpectedly ended"),
                Ok(Async::Ready(Some((packet, from_addr)))) => (packet, from_addr),
            };

            if from_addr != self.remote_public {
                warn!(
                    "Received handshake packet from unrecognized location: {}",
                    from_addr
                );
                continue;
            }

            // make sure it's a handshake packet
            let info = match packet {
                Packet::Control(ControlPacket {
                    control_type: ControlTypes::Handshake(info),
                    ..
                }) => info,
                _ => {
                    warn!("Received non-handshake packet when negotiating rendezvous");
                    continue;
                }
            };

            // update our init seq num
            self.init_seq_num = cmp::max(info.init_seq_num, self.init_seq_num);

            match info.shake_type {
                ShakeType::Waveahand => {
                    // we now respond with a Conclusion packet
                    let new_packet = Packet::Control(ControlPacket {
                        dest_sockid: info.socket_id,
                        timestamp: 0, // TODO: deal with timestamp
                        control_type: ControlTypes::Handshake(HandshakeControlInfo {
                            shake_type: ShakeType::Conclusion,
                            socket_id: self.local_socket_id,
                            peer_addr: self.local_addr,
                            init_seq_num: self.init_seq_num,
                            ..info
                        }),
                    });

                    sock.start_send((new_packet, self.remote_public))?;
                    sock.poll_complete()?;
                }
                ShakeType::Conclusion => {
                    // connection is created, send Agreement back
                    // TODO: if this packet gets dropped, this connection will never init. This is a pretty big bug.
                    let new_packet = Packet::Control(ControlPacket {
                        dest_sockid: info.socket_id,
                        timestamp: 0, // TODO: deal with timestamp,
                        control_type: ControlTypes::Handshake(HandshakeControlInfo {
                            shake_type: ShakeType::Agreement,
                            socket_id: self.local_socket_id,
                            peer_addr: self.local_addr,
                            ..info.clone()
                        }),
                    });

                    sock.start_send((new_packet.clone(), self.remote_public))?;
                    sock.poll_complete()?;

                    // connection is established
                    break (info, Some(new_packet));
                }
                ShakeType::Agreement => {
                    // connection is established
                    break (info, None);
                }
                ShakeType::Induction => {
                    warn!("Received induction handshake while initiating a rendezvous connection. Maybe you tried to pair connect with rendezvous?");
                }
            }
        };

        Ok(Async::Ready(Connected::new(
            self.sock.take().unwrap(),
            ConnectionSettings {
                remote: self.remote_public,
                max_flow_size: info.max_flow_size,
                max_packet_size: info.max_packet_size,
                init_seq_num: info.init_seq_num,
                socket_start_time: Instant::now(), // restamp the socket start time, so TSBPD works correctly
                local_sockid: self.local_socket_id,
                remote_sockid: info.socket_id,
                tsbpd_latency: self.tsbpd_latency, // TODO:
                handshake_returner: Box::new(move |pack| {
                    if let Packet::Control(ControlPacket {
                        control_type: ControlTypes::Handshake(info),
                        ..
                    }) = pack
                    {
                        match info.shake_type {
                            ShakeType::Conclusion => packet.clone(),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }),
            },
        )))
    }
}
