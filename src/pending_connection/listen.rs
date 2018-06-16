use std::{
    collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, io::{Error, ErrorKind},
    net::SocketAddr, time::{Duration, Instant},
};

use futures::prelude::*;

use connected::Connected;
use packet::{ConnectionType, ControlTypes, Packet};
use {ConnectionSettings, SocketID};

pub struct Listen<T> {
    state: ConnectionState,
    sock: Option<T>,
    local_socket_id: SocketID,
    socket_start_time: Instant,
}

impl<T> Listen<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(sock: T, local_socket_id: SocketID, socket_start_time: Instant) -> Listen<T> {
        info!("Listening...");

        Listen {
            sock: Some(sock),
            state: ConnectionState::WaitingForHandshake,
            local_socket_id,
            socket_start_time,
        }
    }
}

// The state of the connection initiation
enum ConnectionState {
    WaitingForHandshake,
    WaitingForCookieResp(i32 /*cookie*/),
    Done(ConnectionSettings),
}

impl<T> Future for Listen<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = Connected<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected<T>, Error> {
        loop {
            let sock = self
                .sock
                .as_mut()
                .expect("Poll after PendingConnection completion");
            sock.poll_complete()?;

            let (packet, addr) = match sock.poll() {
                Ok(Async::Ready(Some(p))) => p,
                Ok(Async::Ready(None)) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "Unexpected EOF when reading stream",
                    ));
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    warn!("Error decoding packet: {:?}", e);

                    continue;
                }
            };

            match self.state {
                // Haven't received anything yet, waiting for the first handshake
                ConnectionState::WaitingForHandshake => {
                    // see if it's a handshake request
                    if let Packet::Control {
                        control_type: ControlTypes::Handshake(shake),
                        timestamp,
                        ..
                    } = packet
                    {
                        info!("Handshake recieved from {:?}", addr);

                        // https://tools.ietf.org/html/draft-gg-udt-03#page-9
                        // When the server first receives the connection request from a client,
                        // it generates a cookie value according to the client address and a
                        // secret key and sends it back to the client. The client must then send
                        // back the same cookie to the server.

                        // generate the cookie, which is just a hash of the address
                        // TODO: the reference impl uses the time, maybe we should here
                        let cookie = {
                            let mut hasher = DefaultHasher::new();
                            shake.peer_addr.hash(&mut hasher);
                            hasher.finish() as i32 // this will truncate, which is fine
                        };

                        // construct a packet to send back
                        let resp_handshake = Packet::Control {
                            timestamp,
                            dest_sockid: shake.socket_id,
                            control_type: ControlTypes::Handshake({
                                let mut tmp = shake;
                                tmp.syn_cookie = cookie;
                                tmp.socket_id = self.local_socket_id;

                                tmp
                            }),
                        };

                        self.state = ConnectionState::WaitingForCookieResp(cookie);

                        // send the packet
                        sock.start_send((resp_handshake, addr))?;
                    }
                }

                // Received the first packet and waiting for the same cookie to come back
                ConnectionState::WaitingForCookieResp(cookie) => {
                    // https://tools.ietf.org/html/draft-gg-udt-03#page-10
                    // The server, when receiving a handshake packet and the correct cookie,
                    // compares the packet size and maximum window size with its own values
                    // and set its own values as the smaller ones. The result values are
                    // also sent back to the client by a response handshake packet, together
                    // with the server's version and initial sequence number. The server is
                    // ready for sending/receiving data right after this step is finished.
                    // However, it must send back response packet as long as it receives any
                    // further handshakes from the same client.

                    info!("Second handshake recieved from {:?}", addr);

                    if let Packet::Control {
                        control_type: ControlTypes::Handshake(shake),
                        timestamp,
                        ..
                    } = packet
                    {
                        if shake.connection_type != ConnectionType::RendezvousRegularSecond {
                            // discard
                            continue;
                        }

                        // check that the cookie matches
                        if shake.syn_cookie != cookie {
                            // wait for the next one
                            warn!(
                                "Received invalid cookie handshake from {:?}: {}, should be {}",
                                addr, shake.syn_cookie, cookie
                            );
                            continue;
                        }

                        info!("Cookie was correct, connection established to {:?}", addr);

                        // select the smaller packet size and max window size
                        // TODO: allow configuration of these parameters, for now just
                        // use the remote ones

                        // construct a packet to send back
                        let resp_handshake = Packet::Control {
                            timestamp,
                            dest_sockid: shake.socket_id,
                            control_type: ControlTypes::Handshake({
                                let mut tmp = shake;
                                tmp.syn_cookie = cookie;
                                tmp.socket_id = self.local_socket_id;

                                tmp
                            }),
                        };

                        // send the packet
                        sock.start_send((resp_handshake, addr))?;
                        // poll_completed here beacuse we won't get a chance to call it later
                        sock.poll_complete()?;

                        // finish the connection
                        self.state = ConnectionState::Done(ConnectionSettings {
                            init_seq_num: shake.init_seq_num,
                            remote_sockid: shake.socket_id,
                            remote: addr,
                            max_flow_size: 16000, // TODO: what is this?
                            max_packet_size: shake.max_packet_size,
                            local_sockid: self.local_socket_id,
                            socket_start_time: self.socket_start_time,
                            tsbpd_latency: Some(Duration::from_millis(120)), // 120 ms by default, TODO: configurable
                        });
                        // break out to end the borrow on self.sock
                        break;
                    }
                }
                // this should never happen
                ConnectionState::Done(_) => unreachable!(),
            }
        }
        match self.state {
            ConnectionState::Done(settings) => Ok(Async::Ready(Connected::new(
                self.sock.take().unwrap(),
                settings,
            ))),
            _ => panic!(),
        }
    }
}
