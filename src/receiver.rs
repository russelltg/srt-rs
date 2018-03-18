use std::io::Error;
use std::time::{Duration, Instant};
use std::net::SocketAddr;

use socket::SrtSocket;
use packet::{AckControlInfo, ControlTypes, Packet};
use bytes::BytesMut;
use futures::prelude::*;
use futures_timer::Interval;

struct LossListEntry {
    seq_num: i32,
    feedback_time: i32,

    // the nubmer of times this entry has been fed back into NAK
    k: i32,
}

enum RSFutureTimeout {
    Recv(Box<Future<Item = (SrtSocket, Option<(SocketAddr, Packet)>), Error = (SrtSocket, Error)>>),
    Send(Box<Future<Item = SrtSocket, Error = Error>>),
}

pub struct Receiver {
    remote: SocketAddr,

    start_time: Instant, // TODO: should this be relative to handshake or creation

    /// the future to send or recieve packets
    future: RSFutureTimeout,
    /// The time to wait for a packet to arrive
    listen_timeout: Duration,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Receiver's Loss List: It is a list of tuples whose values include:
    /// the sequence numbers of detected lost data packets, the latest
    /// feedback time of each tuple, and a parameter k that is the number
    /// of times each one has been fed back in NAK. Values are stored in
    /// the increasing order of packet sequence numbers.
    loss_list: Vec<LossListEntry>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// ACK History Window: A circular array of each sent ACK and the time
    /// it is sent out. The most recent value will overwrite the oldest
    /// one if no more free space in the array.
    ack_history_window: Vec<(i32, i32)>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// PKT History Window: A circular array that records the arrival time
    /// of each data packet.
    packet_history_window: Vec<(i32, i32)>,

    /// When the next ACK packet should be sent
    next_ack_time: Instant,

    /// How long between ACK packets
    ack_duration: Duration,

    /// the highest received packet sequence number
    lrsn: i32,

    next_ack: i32,
}

impl Receiver {
    pub fn new(sock: SrtSocket, remote: SocketAddr) -> Receiver {
        Receiver {
            // TODO: what's the actual timeout
            future: RSFutureTimeout::Recv(sock.recv_packet_timeout(Duration::from_secs(1))),
            listen_timeout: Duration::from_secs(1),
            remote,
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            packet_history_window: Vec::new(),
            next_ack_time: Instant::now() + Duration::from_millis(10),
            lrsn: 0,
            next_ack: 1,
            ack_duration: Duration::from_millis(10),
            start_time: Instant::now(),
        }
    }

    pub fn get_timestamp(&self) -> i32 {
        // TODO: not sure if this should be us or ms
        (self.start_time.elapsed().as_secs() * 1_000_000
            + (self.start_time.elapsed().subsec_nanos() as u64 / 1_000)) as i32
    }

    fn recv_timeout(&self, sock: SrtSocket) -> RSFutureTimeout {
        RSFutureTimeout::Recv(sock.recv_packet_timeout(Duration::from_secs(1)))
    }
}

impl Stream for Receiver {
    type Item = BytesMut;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<BytesMut>, Error> {
        loop {
            // every loop iteration we handle a future or get a NotReady, until we get a NotReady
            // payload is also an option, Some if there's a packet to yield, none for no data
            let (fut, payload) = {
                // wait for the socket to be ready
                let (socket, packet_addr) = match self.future {
                    RSFutureTimeout::Recv(ref mut recv) => match recv.poll() {
                        Err((sock, e)) => {
                            warn!("Error reading packet: {:?}", e);

                            (sock, None)
                        }
                        Ok(Async::Ready(s)) => s,
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                    },

                    RSFutureTimeout::Send(ref mut send) => (try_ready!(send.poll()), None),
                };

                // if there was a packet, handle it
                if let Some((addr, packet)) = packet_addr {
                    match packet {
                        Packet::Control {
                            timestamp,
                            dest_sockid,
                            ref control_type,
                        } => {
                            // handle the control packet

                            match control_type {
                                &ControlTypes::Ack(seq_num, info) => unimplemented!(),
                                &ControlTypes::Ack2(seq_num) => unimplemented!(),
                                &ControlTypes::DropRequest(to_drop, info) => unimplemented!(),
                                &ControlTypes::Handshake(info) => {
                                    // just send it back
                                    // TODO: this should actually depend on where it comesf rom
                                    (
                                        RSFutureTimeout::Send(socket.send_packet(&packet, &addr)),
                                        None,
                                    )
                                }
                                &ControlTypes::KeepAlive => unimplemented!(),
                                &ControlTypes::Nak(ref info) => unimplemented!(),
                                &ControlTypes::Shutdown => unimplemented!(),
                            }
                        }
                        Packet::Data {
                            seq_number,
                            message_loc,
                            in_order_delivery,
                            message_number,
                            timestamp,
                            dest_sockid,
                            payload,
                        } => {
                            // record that we got this packet
                            self.lrsn = seq_number;

                            // see if we need to ACK
                            if Instant::now() > self.next_ack_time {
                                // Send an ACK packet
                                info!("Sending ACK to {:?}...", self.remote);

                                let ack = Packet::Control {
                                    timestamp: self.get_timestamp(),
                                    dest_sockid: 0, // TODO: this should be better
                                    control_type: ControlTypes::Ack(
                                        self.next_ack,
                                        // +1 because it's exclusive
                                        AckControlInfo::new(self.lrsn + 1),
                                    ),
                                };
                                self.next_ack += 1;
                                self.next_ack_time = Instant::now() + self.ack_duration;

                                (
                                    RSFutureTimeout::Send(socket.send_packet(&ack, &self.remote)),
                                    Some(payload),
                                )
                            } else {
                                (self.recv_timeout(socket), Some(payload))
                            }
                        }
                    }
                } else {
                    (self.recv_timeout(socket), None)
                }
            };

            self.future = fut;
            if payload.is_some() {
                return Ok(Async::Ready(payload));
            }
        }
    }
}
