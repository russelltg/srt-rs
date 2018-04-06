use SrtObject;
use bytes::Bytes;
use futures::prelude::*;
use futures_timer::Delay;
use packet::{ControlTypes, Packet, PacketLocation};
use std::collections::VecDeque;
use std::io::{Error, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use CongestionControl;
use congestion_control::{CCData, CCPacketData};

pub struct Sender<T, CC> {
    sock: T,

    /// The congestion control
    congest_ctrl: CC,

    /// The local UDT socket id
    local_sockid: i32,

    /// The start time of the socket
    socket_start_time: Instant,

    /// The remote addr this is connected to
    remote: SocketAddr,

    /// The UDT socket ID of the remote
    remote_sockid: i32,

    /// The list of pending packets
    pending_packets: VecDeque<Bytes>,

    /// The sequence number for the next data packet
    next_seq_number: i32,

    /// The messag number for the next message
    next_message_number: i32,

    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    loss_list: VecDeque<Packet>,

    /// The buffer to store packets for retransmision
    buffer: VecDeque<Packet>,

    /// The first sequence number in buffer, so seq number i would be found at
    /// buffer[i - first_seq]
    first_seq: i32,

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

    /// The send timer
    snd_timer: Delay,
}

impl<T, CC> Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestionControl,
{
    pub fn new(
        sock: T,
        mut congest_ctrl: CC,
        local_sockid: i32,
        socket_start_time: Instant,
        remote: SocketAddr,
        remote_sockid: i32,
        initial_seq_num: i32,
    ) -> Sender<T, CC> {
        Sender {
            sock,
            congest_ctrl,
            local_sockid,
            socket_start_time,
            remote,
            remote_sockid,
            pending_packets: VecDeque::new(),
            next_seq_number: initial_seq_num,
            next_message_number: 0,
            loss_list: VecDeque::new(),
            buffer: VecDeque::new(),
            first_seq: initial_seq_num,
            lr_acked_packet: initial_seq_num,
            rtt: 10_000,
            rtt_var: 0,
            pkt_arr_rate: 0,
            est_link_cap: 0,
            snd_timer: Delay::new(Duration::from_millis(1)),
        }
    }

    fn make_cc_info(&self) -> CCData {
        CCData {
            est_bandwidth: self.est_link_cap,
            max_segment_size: 1316, // TODO,

        }
    }

    fn handle_packet(&mut self, pack: Packet) -> Result<()> {
        match pack {
            Packet::Control {
                control_type,
                .. // Use dst sockid
            } => {
                match control_type {
                    ControlTypes::Ack(seq_num, data) => {
                        // 1) Update the largest acknowledged sequence number, which is the ACK number
                        self.lr_acked_packet = data.ack_number;

                        // 2) Send back an ACK2 with the same ACK sequence number in this ACK.
                        let now = self.get_timestamp();
                        self.sock.start_send((Packet::Control {
                            timestamp: now,
                            dest_sockid: self.remote_sockid,
                            control_type: ControlTypes::Ack2(seq_num),
                        }, self.remote))?;

                        // 3) Update RTT and RTTVar.
                        self.rtt = data.rtt.unwrap_or(0);
                        self.rtt_var = data.rtt_variance.unwrap_or(0);

                        // 4) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                        // TODO: figure out why this makes sense, the sender shouldn't send ACK or NAK packets.

                        // 5) Update flow window size.
                        self.congest_ctrl.on_ack(self);

                        // 6) If this is a Light ACK, stop.
                        // TODO: wat

                        // 7) Update packet arrival rate: A = (A * 7 + a) / 8, where a is the
                        //    value carried in the ACK.
                        self.pkt_arr_rate =
                            (self.pkt_arr_rate * 7 + data.packet_recv_rate.unwrap_or(0)) / 8;

                        // 8) Update estimated link capacity: B = (B * 7 + b) / 8, where b is
                        //    the value carried in the ACK.
                        self.est_link_cap =
                            (self.est_link_cap * 7 + data.est_link_cap.unwrap_or(0)) / 8;

                        // 9) Update sender's buffer (by releasing the buffer that has been
                        //    acknowledged).
                        while data.ack_number > self.first_seq {
                            self.buffer.pop_front();
                            self.first_seq += 1;
                        }

                        // 10) Update sender's loss list (by removing all those that has been
                        //     acknowledged).
                        while let Some(pack) = self.loss_list.pop_front() {
                            if pack.seq_number().unwrap() >= data.ack_number {
                                self.loss_list.push_front(pack);
                            }
                        }
                    }
                    ControlTypes::Ack2(_) => warn!("Sender received ACK2, unusual"),
                    ControlTypes::DropRequest(_msg_id, _info) => unimplemented!(),
                    ControlTypes::Handshake(_shake) => unimplemented!(),
                    // TODO: reset EXP-ish
                    ControlTypes::KeepAlive => {}
                    ControlTypes::Nak(_info) => {}
                    ControlTypes::Shutdown => unimplemented!(),
                }
            }
            Packet::Data { .. } => warn!("Sender received data packet"),
        }

        Ok(())
    }

    fn send_packet(&mut self, payload: Bytes) -> Result<()> {
        let pack = Packet::Data {
            dest_sockid: self.remote_sockid,
            in_order_delivery: false, // TODO: research this
            message_loc: PacketLocation::Only,
            message_number: {
                self.next_message_number += 1;

                self.next_message_number - 1
            },
            seq_number: {
                self.next_seq_number += 1;

                self.next_seq_number - 1
            },
            timestamp: self.get_timestamp(), // TODO: allow senders to put their own timestamps here
            payload,
        };
        self.sock.start_send((pack, self.remote))?;

        Ok(())
    }
}

impl<T, CC> Sink for Sender<T, CC>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
    CC: CongestionControl,
{
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, item: Bytes) -> StartSend<Bytes, Error> {
        self.pending_packets.push_back(item);

        Ok(AsyncSink::Ready)
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
                // TODO: implement congestion control
                let packet = self.loss_list.pop_front().unwrap();

                self.sock.start_send((packet, self.remote))?;
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
                {
                    let pack_to_send = match self.pending_packets.pop_front() {
                        Some(p) => p,
                        None => return Ok(Async::Ready(())),
                    };
                    self.send_packet(pack_to_send)?;
                }

                // 5) If the sequence number of the current packet is 16n, where n is an
                //     integer, go to 2) (which is send another packet).
                if (self.next_seq_number - 1) % 16 == 0 {
                    let payload = match self.pending_packets.pop_front() {
                        Some(p) => p,
                        None => return Ok(Async::Ready(())),
                    };
                    self.send_packet(payload)?;
                    continue;
                }
            }

            // 6) Wait (SND - t) time, where SND is the inter-packet interval
            //     updated by congestion control and t is the total time used by step
            //     1 to step 5. Go to 1).

            // TODO: update SND duration
            self.congest_ctrl.on_packet_sent(self);

            self.snd_timer.reset(self.congest_ctrl.send_interval());
        }
    }

    fn close(&mut self) -> Poll<(), Error> {
        // TODO: send shutdown packet
        self.poll_complete()
    }
}

impl<T, CC> SrtObject for Sender<T, CC> {
    fn packet_arrival_rate(&self) -> i32 {
        unimplemented!()
    }

    fn rtt(&self) -> Duration {
        unimplemented!()
    }

    fn estimated_bandwidth(&self) -> i32 {
        unimplemented!()
    }

    /// Receiver doesn't have this info, so yields None
    fn packet_send_rate(&self) -> Option<i32> {
        unimplemented!()
    }

    /// The maximum packet size, in bytes
    fn max_packet_size(&self) -> i32 {
        unimplemented!()
    }

    fn start_time(&self) -> Instant {
        self.socket_start_time
    }

    /// Get the SRT timestamp, which is microseconds since `start_time`.
    fn get_timestamp(&self) -> i32 {
        let elapsed = self.start_time().elapsed();

        (elapsed.as_secs() * 1_000_000 + (u64::from(elapsed.subsec_nanos()) / 1_000)) as i32
    }
}
