use std::io::{Error, ErrorKind};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::mem;

use futures::prelude::*;

use socket::SrtSocket;
use packet::{ControlTypes, Packet};

pub struct PendingConnection {
    conn_type: ConnectionType,
    state: ConnectionState,
}

// The state of the connection initiation
enum ConnectionState {
    WaitingForHandshake,
    WaitingForCookieResp(i32 /*cookie*/),
}

enum ConnectionType {
    Listen,
    Connect(SocketAddr),
    Rendezvous {
        local_public: SocketAddr,
        remote_public: SocketAddr,
    },
}

impl PendingConnection {
    pub fn listen() -> PendingConnection {
        PendingConnection {
            conn_type: ConnectionType::Listen,
            state: ConnectionState::WaitingForHandshake,
        }
    }

    pub fn connect(remote_addr: SocketAddr) -> PendingConnection {
        PendingConnection {
            conn_type: ConnectionType::Connect(remote_addr),
            state: ConnectionState::WaitingForHandshake,
        }
    }

    pub fn rendezvous(
        local_public: SocketAddr,
        remote_public: SocketAddr,
    ) -> PendingConnection {
        PendingConnection {
            conn_type: ConnectionType::Rendezvous {
                local_public,
                remote_public,
            },
            state: ConnectionState::WaitingForHandshake,
        }
    }
    

    fn poll_with(&mut self, sock: &mut SrtSocket) -> Poll<SocketAddr, Error> {

        loop {
            match self.conn_type {
                ConnectionType::Listen => {
                    // wait for a packet
                    let (packet, addr) = match try_ready!(sock.poll()) {
                        Some(p) => p,

                        // this happens if the packet stream closes
                        None => {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "End of packet stream found when searching for handshake packet",
                            ));
                        }
                    };

                    match self.state {
                        // Haven't received anything yet, waiting for the first handshake
                        ConnectionState::WaitingForHandshake => {
                            // see if it's a handshake request
                            if let Packet::Control {
                                control_type: ControlTypes::Handshake(shake),
                                timestamp,
                                dest_sockid,
                            } = packet
                            {
                                // https://tools.ietf.org/html/draft-gg-udt-03#page-9
                                // When the server first receives the connection request from a client,
                                // it generates a cookie value according to the client address and a
                                // secret key and sends it back to the client. The client must then send
                                // back the same cookie to the server.

                                // generate the cookie, which is just a hash of the address
                                // TODO: the reference impl uses the time, maybe we should here
                                let mut hasher = DefaultHasher::new();
                                shake.peer_addr.hash(&mut hasher);
                                let cookie = hasher.finish() as i32; // this will truncate, which is fine

                                // construct a packet to send back
                                let mut shake_resp = shake.clone();
                                shake_resp.syn_cookie = cookie;
                                let resp_handshake = Packet::Control {
                                    timestamp,
                                    dest_sockid,
                                    control_type: ControlTypes::Handshake(shake_resp),
                                };

                                // queue the send
                                // TODO: is this unwrap safe?
                                sock.queue_sender.send((resp_handshake, addr)).unwrap();

                                self.state = ConnectionState::WaitingForCookieResp(cookie);

                                println!(
                                    "Got a first handshake, waiting for the cookie resp. Cookie: {}",
                                    cookie
                                );
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

                            if let Packet::Control {
                                control_type: ControlTypes::Handshake(ref shake),
                                ..
                            } = packet
                            {
                                // check that the cookie matches
                                if shake.syn_cookie != cookie {
                                    // wait for the next one
                                    println!(
                                        "Received invalid cookie handshake: {}",
                                        shake.syn_cookie
                                    );
                                    continue;
                                }

                                // select the smaller packet size and max window size
                                // TODO: allow configuration of these parameters, for now just
                                // use the remote ones

                                // send the same packet back, just use the remote inital sequence number TODO: is that right?
                                sock.queue_sender.send((packet.clone(), addr)).unwrap();

                                return Ok(Async::Ready(addr))
                            }
                        }
                    }
                }
                ConnectionType::Connect(_) => unimplemented!(),
                ConnectionType::Rendezvous { .. } => unimplemented!(),
            };
        }
    }
}
