use std::io::{Error, ErrorKind};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::mem;

use futures::prelude::*;

use connection::Connection;
use socket::SrtSocket;
use packet::{ControlTypes, Packet};
use receiver::Receiver;

pub struct PendingConnection {
    conn_type: ConnectionType,
    state: ConnectionState,
    sock: Option<SrtSocket>,
}

// The state of the connection initiation
enum ConnectionState {
    WaitingForHandshake,
    WaitingForCookieResp(i32 /*cookie*/),
    Done(SocketAddr, i32, i32),
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
    pub fn listen(sock: SrtSocket) -> PendingConnection {
        PendingConnection {
            sock: Some(sock),
            conn_type: ConnectionType::Listen,
            state: ConnectionState::WaitingForHandshake,
        }
    }

    pub fn connect(_sock: SrtSocket, _remote_addr: SocketAddr) -> PendingConnection {
        unimplemented!()
    }

    pub fn rendezvous(
        _sock: SrtSocket,
        _local_public: SocketAddr,
        _remote_public: SocketAddr,
    ) -> PendingConnection {
        unimplemented!()
    }
}

impl Future for PendingConnection {
    type Item = Connection;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connection, Error> {
        // the wakeup could be becaus of poll_complete, handle that

        loop {
            let sock = self.sock
                .as_mut()
                .expect("Poll after PendingConnection completion");

            sock.poll_complete()?;

            match self.conn_type {
                ConnectionType::Listen => {
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
                                        let mut tmp = shake.clone();
                                        tmp.syn_cookie = cookie;
                                        tmp.socket_id = sock.id();

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
                                control_type: ControlTypes::Handshake(ref shake),
                                timestamp,
                                ..
                            } = packet
                            {
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
                                        let mut tmp = shake.clone();
                                        tmp.syn_cookie = cookie;
                                        tmp.socket_id = sock.id();

                                        tmp
                                    }),
                                };

                                // send the packet
                                sock.start_send((resp_handshake, addr))?;
                                // poll_completed here beacuse we won't get a chance to call it later
                                sock.poll_complete()?;

                                // finish the connection
                                self.state = ConnectionState::Done(
                                    addr,
                                    shake.socket_id,
                                    shake.init_seq_num,
                                );
                                // break out to end the borrow on self.sock
                                break;
                            }
                        }
                        // this should never happen
                        ConnectionState::Done(_, _, _) => panic!(),
                    }
                }
                ConnectionType::Connect(_) => unimplemented!(),
                ConnectionType::Rendezvous { .. } => unimplemented!(),
            };

            sock.poll_complete()?;
        }

        match self.state {
            ConnectionState::Done(addr, sockid, init_seq) => {
                return Ok(Async::Ready(Connection::Recv(Receiver::new(
                    mem::replace(&mut self.sock, None).unwrap(),
                    addr,
                    sockid,
                    init_seq,
                ))))
            }
            _ => panic!(),
        }
    }
}
