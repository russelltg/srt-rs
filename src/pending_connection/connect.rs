use std::{
    net::{IpAddr, SocketAddr}, time::{Duration, Instant},
};

use failure::Error;
use futures::prelude::*;
use futures_timer::Interval;

use rand::{thread_rng, Rng};

use connected::Connected;
use packet::{
    ConnectionType, ControlPacket, ControlTypes, HandshakeControlInfo, Packet, SocketType,
};
use ConnectionSettings;
use SeqNumber;
use SocketID;

pub struct Connect<T> {
    remote: SocketAddr,
    sock: Option<T>,
    local_socket_id: SocketID,
    socket_start_time: Instant,
    init_seq_num: SeqNumber,

    state: State,

    send_interval: Interval,
    local_addr: IpAddr,
}

enum State {
    Starting,
    First(Packet),
}

impl<T> Connect<T> {
    pub fn new(
        sock: T,
        remote: SocketAddr,
        local_socket_id: SocketID,
        socket_start_time: Instant,
        local_addr: IpAddr,
    ) -> Connect<T> {
        info!("Connecting to {:?}", remote);

        Connect {
            remote,
            sock: Some(sock),
            local_socket_id,
            socket_start_time,
            init_seq_num: thread_rng().gen::<SeqNumber>(),
            send_interval: Interval::new(Duration::from_millis(100)),
            state: State::Starting,
            local_addr,
        }
    }
}

impl<T> Future for Connect<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        self.sock.as_mut().unwrap().poll_complete()?;

        // handle incoming packets
        while let Async::Ready(Some((pack, addr))) = self.sock.as_mut().unwrap().poll()? {
            // make sure it's the right addr
            if self.remote != addr {
                continue;
            }

            if let Packet::Control(ControlPacket {
                timestamp,
                dest_sockid,
                control_type: ControlTypes::Handshake(info),
            }) = pack
            {
                // make sure the sockid is right
                if dest_sockid != self.local_socket_id {
                    continue;
                }

                match self.state {
                    State::Starting => {
                        info!("Got first handshake packet from {:?}", addr);

                        // send back the same SYN cookie
                        let pack_to_send = Packet::Control(ControlPacket {
                            dest_sockid: SocketID(0), // zero because still initiating connection
                            timestamp,
                            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                                socket_id: self.local_socket_id,
                                connection_type: ConnectionType::RendezvousRegularSecond,
                                ..info
                            }),
                        });

                        self.sock
                            .as_mut()
                            .unwrap()
                            .start_send((pack_to_send.clone(), self.remote))?;
                        self.sock.as_mut().unwrap().poll_complete()?;

                        // move on to the next stage
                        self.state = State::First(pack_to_send);
                    }
                    State::First(_) => {
                        if info.connection_type != ConnectionType::RendezvousRegularSecond {
                            info!(
                                "Was waiting for -1 connection type, got {:?}",
                                info.connection_type
                            );
                            // discard
                            continue;
                        }

                        info!("Got second handshake, connection established to {:?}", addr);

                        // this packet has the final settings in it, and after this the connection is done
                        return Ok(Async::Ready(Connected::new(
                            self.sock.take().unwrap(),
                            ConnectionSettings {
                                remote: self.remote,
                                max_flow_size: info.max_flow_size,
                                max_packet_size: info.max_packet_size,
                                init_seq_num: info.init_seq_num,
                                socket_start_time: self.socket_start_time,
                                local_sockid: self.local_socket_id,
                                remote_sockid: info.socket_id,
                                tsbpd_latency: Some(Duration::from_millis(120)), // 120 ms by default, TODO: configurable
                            },
                        )));
                    }
                }
            } else {
                info!("Non-handshake packet received during handshake phase")
            }
        }

        loop {
            try_ready!(self.send_interval.poll());

            info!("Sending handshake packet to: {:?}", self.remote);

            match self.state {
                State::Starting => {
                    // send a handshake
                    self.sock.as_mut().unwrap().start_send((
                        Packet::Control(ControlPacket {
                            dest_sockid: SocketID(0),
                            timestamp: 0,
                            control_type: ControlTypes::Handshake(HandshakeControlInfo {
                                udt_version: 4,
                                init_seq_num: self.init_seq_num,
                                max_packet_size: 1500, // TODO: take as a parameter
                                max_flow_size: 8192,   // TODO: take as a parameter
                                socket_id: self.local_socket_id,
                                connection_type: ConnectionType::Regular,
                                peer_addr: self.local_addr,
                                sock_type: SocketType::Datagram,
                                syn_cookie: 0,
                            }),
                        }),
                        self.remote,
                    ))?;
                    self.sock.as_mut().unwrap().poll_complete()?;
                }
                State::First(ref pack) => {
                    self.sock
                        .as_mut()
                        .unwrap()
                        .start_send((pack.clone(), self.remote))?;
                    self.sock.as_mut().unwrap().poll_complete()?;
                }
            }
        }
    }
}
