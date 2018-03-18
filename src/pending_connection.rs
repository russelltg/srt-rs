use std::io::Error;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

use futures::prelude::*;

use connection::Connection;
use socket::SrtSocket;
use packet::{ControlTypes, Packet};
use receiver::Receiver;

pub struct PendingConnection {
    conn_type: ConnectionType,
    state: ConnectionState,
    future: RSFuture,
}

enum RSFuture {
    Recv(Box<Future<Item = (SrtSocket, SocketAddr, Packet), Error = (SrtSocket, Error)>>),
    Snd(Box<Future<Item = SrtSocket, Error = Error>>),
}

impl RSFuture {
    fn sender(&mut self) -> Option<&mut Box<Future<Item = SrtSocket, Error = Error>>> {
        match self {
            &mut RSFuture::Recv(_) => None,
            &mut RSFuture::Snd(ref mut s) => Some(s),
        }
    }

    fn _receiver(
        &mut self,
    ) -> Option<&mut Box<Future<Item = (SrtSocket, SocketAddr, Packet), Error = (SrtSocket, Error)>>>
    {
        match self {
            &mut RSFuture::Recv(ref mut r) => Some(r),
            &mut RSFuture::Snd(_) => None,
        }
    }
}

// The state of the connection initiation
enum ConnectionState {
    WaitingForHandshake,
    WaitingForCookieResp(i32 /*cookie*/),
    Done(SocketAddr, i32 /*socketid*/, i32 /*init_seq_num*/),
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
            future: RSFuture::Recv(sock.recv_packet()),
            conn_type: ConnectionType::Listen,
            state: ConnectionState::WaitingForHandshake,
            // TODO: should this be random?
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
        loop {
            match self.conn_type {
                ConnectionType::Listen => {
                    let (sock, addr, packet) = match self.future {
                        ref mut fut @ RSFuture::Snd(_) => {
                            let sock = try_ready!(fut.sender().unwrap().poll());

                            if let ConnectionState::Done(addr, remote_socketid, init_seq_num) =
                                self.state
                            {
                                return Ok(Async::Ready(Connection::Recv(Receiver::new(
                                    sock,
                                    addr,
                                    remote_socketid,
                                    init_seq_num,
                                ))));
                            }

                            *fut = RSFuture::Recv(sock.recv_packet());

                            continue;
                        }
                        RSFuture::Recv(ref mut fut) => match fut.poll() {
                            Err((sock, e)) => {
                                warn!("Error decoding packet: {:?}", e);

                                *fut = sock.recv_packet();
                                continue;
                            }
                            Ok(Async::Ready(d)) => d,
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                        },
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
                                self.future =
                                    RSFuture::Snd(sock.send_packet(&resp_handshake, &addr))
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
                                    trace!(
                                        "Received invalid cookie handshake from {:?}: {}, should be {}",
                                        addr, shake.syn_cookie, cookie
                                    );
                                    continue;
                                }

                                trace!("Cookie was correct, connection established to {:?}", addr);

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
                                self.future =
                                    RSFuture::Snd(sock.send_packet(&resp_handshake, &addr));

                                // don't just return now, wait until the packet is sent
                                self.state = ConnectionState::Done(
                                    addr,
                                    shake.socket_id,
                                    shake.init_seq_num,
                                );
                            }
                        }
                        // This is handled further up
                        ConnectionState::Done(_, _, _) => panic!(),
                    }
                }
                ConnectionType::Connect(_) => unimplemented!(),
                ConnectionType::Rendezvous { .. } => unimplemented!(),
            };
        }
    }
}
