use std::io::{Error, Result};
use std::net::SocketAddr;
use std::collections::VecDeque;

use bytes::Bytes;
use futures::prelude::*;

use packet::{ControlTypes, Packet};
use socket::SrtSocket;

pub struct Sender {
    sock: SrtSocket,

    /// The remote addr this is connected to
    remote: SocketAddr,

    /// The UDT socket ID of the remote
    remote_sockid: i32,

    /// The list of pending packets
    pending_packets: VecDeque<Bytes>,

    /// The sequence number for the next data packet
    next_seq_number: i32,

    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    loss_list: VecDeque<Packet>,

    /// The sequence number of the largest acknowledged packet + 1
    lr_acked_packet: i32,

    /// Round trip time
    rtt: i32,

    /// Round trip time variance
    rtt_var: i32,

    /// packet arrival rate
    pkt_arr_rate: i32,

    /// estimated link capacity
    est_link_cap: i32,
}

impl Sender {
    pub fn new(
        sock: SrtSocket,
        remote: SocketAddr,
        remote_sockid: i32,
        initial_seq_num: i32,
    ) -> Sender {
        Sender {
            sock,
            remote,
            remote_sockid,
            pending_packets: VecDeque::new(),
            next_seq_number: initial_seq_num,
            loss_list: VecDeque::new(),
            lr_acked_packet: initial_seq_num,
            rtt: 10_000,
            rtt_var: 0,
            pkt_arr_rate: 0,
            est_link_cap: 0,
        }
    }

    fn handle_packet(&mut self, pack: Packet) -> Result<()> {
        match pack {
            Packet::Control {
                timestamp,
                control_type,
                .. // Use dst sockid
            } => {
                match control_type {
                    ControlTypes::Ack(seq_num, data) => {
                        // 1) Update the largest acknowledged sequence number, which is the ACK number
                        self.lr_acked_packet = data.ack_number;

                        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
                        let now = self.sock.get_timestamp();
                        self.sock.start_send(Packet::Control {
                            timestamp: now,
                            dest_sockid: self.remote_sockid,
                            contorl_type: ControlTypes::Ack2(seq_num),
                        })?;
                        
                        // 3) Update RTT and RTTVar.
                        self.rtt = data.rtt;
                        self.rtt_var = data.rtt_var;

                        // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                        // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.
   
                        // 5) Update flow window size.
                        self.flow_window_size = data.flow_window_size;
                        
                        // 6) If this is a Light ACK, stop.
                        // TODO: wat

                        // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
                        //    value carried in the ACK.
                        self.pkt_arr_rate = (self.pkt_arr_rate * 7 + data.packet_recv_rate) / 8;

                        // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
                        //    the value carried in the ACK.
                        self.est_link_cap = (self.est_link_cap * 7 + data.est_link_cap) / 8;

                        // 9) Update sender's buffer (by releasing the buffer that has been
                        //    acknowledged).
                           
                        // TODO: 

                        // 10) Update sender's loss list (by removing all those that has been
                        //     acknowledged).

                        // TODO:
                    },
                    ControlTypes::Ack2(_) => warn!("Sender received ACK2, unusual"),
                    ControlTypes::DropRequest(_msg_id, _info) => unimplemented!(),
                    ControlTypes::Handshake(_shake) => unimplemented!(),
                    ControlTypes::KeepAlive => unimplemented!(),
                    ControlTypes::Nak(_info) => unimplemented!(),
                    ControlTypes::Shutdown => unimplemented!(),
                }
            }
        }

        Ok(())
    }
}

impl Sink for Sender {
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {
        self.pending_packets.push_back(item);

        return Ok(AsyncSink::Ready);
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        loop {
            // do we have any packets to handle?
            if let Async::Ready(Some((pack, _addr))) = self.sock.poll()? {
                // TODO: use addr
                self.handle_packet(pack)?;
            }

            // 1) If the sender's loss list is not empty,
            if !self.loss_list.is_empty() {
                // retransmit the first
                // packet in the list and remove it from the list.

                // get the payload
                let packet = self.loss_list.pop_front().unwrap();

                self.sock.start_send((packet, self.remote));
            } else {
                // 2) In messaging mode, if the packets has been the loss list for a
                //    time more than the application specified TTL (time-to-live), send
                //    a message drop request and remove all related packets from the
                //    loss list. Go to 1).

                // TODO: I honestly don't know what this means

                // a. If the number of unacknowledged packets exceeds the
                //    flow/congestion window size, wait until an ACK comes. Go to
                //    1).
                // b. Pack a new data packet and send it out.

            }

            // 5
        }
    }

    fn close(&mut self) -> Poll<(), Error> {}
}
