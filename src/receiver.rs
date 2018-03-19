use std::io::{Error, Result};
use std::time::Duration;
use std::net::SocketAddr;
use std::cmp;

use socket::SrtSocket;
use packet::{AckControlInfo, ControlTypes, NakControlInfo, Packet};
use bytes::Bytes;
use futures::prelude::*;
use futures_timer::{Delay, Interval};

struct LossListEntry {
    seq_num: i32,

    // last time it was feed into NAK
    feedback_time: i32,

    // the nubmer of times this entry has been fed back into NAK
    k: i32,
}

// TODO: write tests for this, cuz it's often hard to get right
fn generated_compressed_loss(loss_list: &Vec<LossListEntry>) -> Vec<i32> {
    let mut ret = Vec::new();

    // The loss information carried in an NAK packet is an array of 32-bit
    // integers. If an integer in the array is a normal sequence number (1st
    // bit is 0), it means that the packet with this sequence number is
    // lost; if the 1st bit is 1, it means all the packets starting from
    // (including) this number to (including) the next number in the array
    // (whose 1st bit must be 0) are lost.

    let mut i = 0;
    while i < loss_list.len() {
        let seq_num = loss_list[i].seq_num;
        // should we start a range?
        if i + 1 < loss_list.len() && loss_list[i].seq_num == seq_num + 1 {
            ret.push(seq_num | 1 << 31);
            i += 1;
            // how far should the range go?
            let mut range_end = seq_num + 1;
            while i + 1 < loss_list.len() && loss_list[i].seq_num == range_end + 1 {
                range_end += 1;
                i += 1;
            }

            ret.push(range_end)
        } else {
            ret.push(seq_num);
        }

        i += 1;
    }

    ret
}

pub struct Receiver {
    remote: SocketAddr,
    remote_sockid: i32,

    /// the round trip time, in microseconds
    /// is calculated each ACK2
    rtt: i32,

    /// the round trip time variance, in microseconds
    /// is calculated each ACK2
    rtt_variance: i32,

    /// the future to send or recieve packets
    sock: SrtSocket,

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

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Packet Pair Window: A circular array that records the time
    /// interval between each probing packet pair.
    ///
    /// First is seq num, second is time
    packet_pair_window: Vec<(i32, i32)>,

    /// Wakes the thread when an ACK is to be sent
    ack_interval: Interval,

    /// the highest received packet sequence number
    lrsn: i32,

    /// The number of consecutive timeouts
    exp_count: i32,

    /// The ID of the next ack packet
    next_ack: i32,

    /// The timestamp of the probe time
    /// Used to see duration between packets
    probe_time: Option<i32>,

    timeout_timer: Delay,
}

enum ReadyType {
    Packet(Bytes),
    Shutdown,
}

impl Receiver {
    pub fn new(
        sock: SrtSocket,
        remote: SocketAddr,
        remote_sockid: i32,
        initial_seq_num: i32,
    ) -> Receiver {
        Receiver {
            remote,
            remote_sockid,
            // TODO: what's the actual timeout
            sock,
            rtt: 10_000,
            rtt_variance: 1_000,
            listen_timeout: Duration::from_secs(1),
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            packet_history_window: Vec::new(),
            packet_pair_window: Vec::new(),
            ack_interval: Interval::new(Duration::from_millis(10)),
            lrsn: initial_seq_num - 1,
            next_ack: 1,
            exp_count: 1,
            probe_time: None,
            timeout_timer: Delay::new(Duration::from_secs(1)),
        }
    }

    fn reset_timeout(&mut self) {
        self.timeout_timer.reset(self.listen_timeout)
    }

    fn check_ack_timer(&mut self) -> Result<()> {
        match self.ack_interval.poll() {
            Err(e) => panic!(e),
            Ok(Async::NotReady) => return Ok(()),
            Ok(Async::Ready(_)) => {}
        }

        // Send an ACK packet
        let ts = self.sock.get_timestamp();

        let ack = self.make_control_packet(ControlTypes::Ack(
            self.next_ack,
            AckControlInfo {
                // +1 because it's exclusive
                recvd_until: self.lrsn + 1,
                rtt: Some(self.rtt),
                rtt_variance: Some(self.rtt_variance),
                buffer_available: None, // TODO: add these
                packet_recv_rate: None,
                est_link_cap: None,
            },
        ));

        // add it to the ack history
        self.ack_history_window.push((self.next_ack, ts));

        self.next_ack += 1;

        self.sock.start_send((ack, self.remote.clone()))?;

        Ok(())
    }

    // checks the timers
    // if a timer was triggered, then an RSFutureTimeout will be returned
    // if not, the socket is given back
    fn check_timers(&mut self) -> Result<()> {
        // see if we need to ACK

        self.check_ack_timer()?;

        // TODO: add NAK

        Ok(())
    }

    // handles a packet, returning either a future, if there is something to send,
    // or the socket, and in the case of a data packet, a payload
    fn handle_packet(&mut self, packet: Packet, from: &SocketAddr) -> Result<Option<ReadyType>> {
        match packet {
            Packet::Control { control_type, .. } => {
                // handle the control packet

                // TODO: check incoming socket id

                match control_type {
                    ControlTypes::Ack(_seq_num, _info) => unimplemented!(),
                    ControlTypes::Ack2(seq_num) => {
                        // 1) Locate the related ACK in the ACK History Window according to the
                        //    ACK sequence number in this ACK2.
                        let id_in_wnd = match self.ack_history_window
                            .as_slice()
                            .binary_search_by(|&(seq, _)| seq.cmp(&seq_num))
                        {
                            Ok(i) => Some(i),
                            Err(_) => None,
                        };

                        if let Some(id) = id_in_wnd {
                            let (_, send_timestamp) = self.ack_history_window[id];

                            // 2) Update the largest ACK number ever been acknowledged.
                            // TODO: actually do this. Not sure why it's necessary

                            // 3) Calculate new rtt according to the ACK2 arrival time and the ACK
                            //    departure time, and update the RTT value as: RTT = (RTT * 7 +
                            //    rtt) / 8
                            let immediate_rtt = self.sock.get_timestamp() - send_timestamp;
                            self.rtt = (self.rtt * 7 + immediate_rtt) / 8;

                            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
                            self.rtt_variance = (self.rtt_variance * 3
                                + (self.rtt_variance - immediate_rtt).abs())
                                / 4;

                            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                            self.ack_interval = Interval::new(Duration::new(
                                0,
                                // convert to nanoseconds
                                (4 * self.rtt + self.rtt_variance + 0) as u32 * 1_000, /* TODO: syn */
                            ));
                        } else {
                            warn!(
                                "ACK sequence number in ACK2 packet not found in ACK history: {}",
                                seq_num
                            );
                        }
                    }
                    ControlTypes::DropRequest(_to_drop, _info) => unimplemented!(),
                    ControlTypes::Handshake(info) => {
                        // just send it back
                        // TODO: this should actually depend on where it comes from & dest sock id
                        let sockid = self.sock.id();

                        let ts = self.sock.get_timestamp();
                        self.sock.start_send((
                            Packet::Control {
                                timestamp: ts,
                                dest_sockid: info.socket_id, // this is different, so don't use make_control_packet
                                control_type: ControlTypes::Handshake({
                                    let mut tmp = info.clone();
                                    tmp.socket_id = sockid;
                                    tmp
                                }),
                            },
                            *from,
                        ))?;
                    }
                    ControlTypes::KeepAlive => {} // TODO: actually reset EXP etc
                    ControlTypes::Nak(_info) => unimplemented!(),
                    ControlTypes::Shutdown => return Ok(Some(ReadyType::Shutdown)), // end of stream
                }
            }
            Packet::Data {
                seq_number,
                payload,
                ..
            } => {
                let now = self.sock.get_timestamp();

                // 1) Reset the ExpCount to 1. If there is no unacknowledged data
                //     packet, or if this is an ACK or NAK control packet, reset the EXP
                //     timer.
                self.exp_count = 1;

                // 2&3 don't apply

                // 4) If the sequence number of the current data packet is 16n + 1,
                //     where n is an integer, record the time interval between this
                if seq_number % 16 == 0 {
                    self.probe_time = Some(now)
                } else if seq_number % 16 == 1 {
                    // if there is an entry
                    if let Some(pt) = self.probe_time {
                        // calculate and insert
                        self.packet_pair_window.push((seq_number, now - pt));

                        // reset
                        self.probe_time = None;
                    }
                }
                // 5) Record the packet arrival time in PKT History Window.
                self.packet_history_window.push((seq_number, now));

                // 6)
                // a. If the sequence number of the current data packet is greater
                //    than LRSN + 1, put all the sequence numbers between (but
                //    excluding) these two values into the receiver's loss list and
                //    send them to the sender in an NAK packet.
                if seq_number > self.lrsn + 1 {
                    for i in (self.lrsn + 1)..seq_number {
                        self.loss_list.push(LossListEntry {
                            seq_num: i,
                            feedback_time: now,
                            k: 1,
                        })
                    }

                    self.send_nak()?;

                // b. If the sequence number is less than LRSN, remove it from the
                //    receiver's loss list.
                } else if seq_number < self.lrsn {
                    match self.loss_list[..].binary_search_by(|ref ll| ll.seq_num.cmp(&seq_number))
                    {
                        Ok(i) => {
                            self.loss_list.remove(i);
                            ()
                        }
                        Err(_) => {
                            trace!(
                                "Packet received that's not in the loss list: {}",
                                seq_number
                            );
                        }
                    };
                }

                // record that we got this packet
                self.lrsn = cmp::max(seq_number, self.lrsn);

                return Ok(Some(ReadyType::Packet(payload)));
            }
        };

        Ok(None)
    }

    // send a NAK, and return the future
    fn send_nak(&mut self) -> Result<()> {
        info!("Sending NAK");

        let pack = self.make_control_packet(ControlTypes::Nak(NakControlInfo {
            loss_info: generated_compressed_loss(&self.loss_list),
        }));

        // update the loss list
        for ref mut l in &mut self.loss_list {
            l.k += 1;
            l.feedback_time = self.sock.get_timestamp();
        }

        self.sock.start_send((pack, self.remote))?;

        Ok(())
    }

    fn make_control_packet(&self, control_type: ControlTypes) -> Packet {
        Packet::Control {
            timestamp: self.sock.get_timestamp(),
            dest_sockid: self.remote_sockid,
            control_type,
        }
    }
}

impl Stream for Receiver {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, Error> {
        self.check_timers()?;

        self.sock.poll_complete()?;

        loop {
            match self.timeout_timer.poll() {
                Err(e) => panic!(e), // why would this ever happen
                Ok(Async::Ready(_)) => {
                    self.exp_count += 1;
                    self.reset_timeout();
                }
                Ok(Async::NotReady) => {}
            }

            let (packet, addr) = match self.sock.poll() {
                Err(e) => {
                    warn!("Error reading packet: {:?}", e);

                    continue;
                }
                Ok(Async::Ready(Some(p))) => p,
                Ok(Async::Ready(None)) => {
                    // end of stream, shutdown

                    return Ok(Async::Ready(None));
                }
                // TODO: exp_count
                Ok(Async::NotReady) => return Ok(Async::NotReady),
            };

            // handle the socket
            // packet was received, reset exp_count
            self.exp_count = 1;
            self.reset_timeout();

            let res = self.handle_packet(packet, &addr)?;

            // TODO: should this be here for optimal performance?
            self.sock.poll_complete()?;

            match res {
                None => continue,
                Some(ReadyType::Packet(p)) => return Ok(Async::Ready(Some(p))),
                Some(ReadyType::Shutdown) => return Ok(Async::Ready(None)),
            }
        }
    }
}
