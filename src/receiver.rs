use std::cmp;
use std::io::{Error, Result};
use std::iter::Iterator;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::prelude::*;
use futures_timer::{Delay, Interval};
use packet::{AckControlInfo, ControlTypes, NakControlInfo, Packet};
use loss_compression::compress_loss_list;

struct LossListEntry {
    seq_num: i32,

    // last time it was feed into NAK
    feedback_time: i32,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: i32,

    /// the ack sequence number
    ack_seq_num: i32,

    /// timestamp that it was sent at
    timestamp: i32,
}


pub struct Receiver<T> {
    remote: SocketAddr,
    remote_sockid: i32,

    /// the round trip time, in microseconds
    /// is calculated each ACK2
    rtt: i32,

    /// the round trip time variance, in microseconds
    /// is calculated each ACK2
    rtt_variance: i32,

    /// The socket ID of the local UDT entry
    local_sockid: i32,

    /// the future to send or recieve packets
    sock: T,

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
    ack_history_window: Vec<AckHistoryEntry>,

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

    /// Wakes the thread when an ACK or a NAK is to be sent
    ack_interval: Interval,

    /// the highest received packet sequence number + 1
    lrsn: i32,

    /// The number of consecutive timeouts
    exp_count: i32,

    /// The ID of the next ack packet
    next_ack: i32,

    /// The timestamp of the probe time
    /// Used to see duration between packets
    probe_time: Option<i32>,

    timeout_timer: Delay,

    /// The ACK sequence number of the largest ACK2 received, and the ack number
    lr_ack_acked: (i32, i32),

    /// The socket start time, timestamp zero
    sock_start_time: Instant,
}

enum ReadyType {
    Packet(Bytes),
    Shutdown,
}

impl<T> Receiver<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(
        sock: T,
        remote: SocketAddr,
        remote_sockid: i32,
        initial_seq_num: i32,
        local_sockid: i32,
        sock_start_time: Instant,
    ) -> Receiver<T> {
        Receiver {
            remote,
            remote_sockid,
            // TODO: what's the actual timeout
            sock,
            local_sockid,
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
            lr_ack_acked: (0, 0),
            sock_start_time,
        }
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    fn reset_timeout(&mut self) {
        self.timeout_timer.reset(self.listen_timeout)
    }

    fn on_ack_event(&mut self) -> Result<()> {
        // get largest inclusive received packet number
        let ack_number = match self.loss_list.first() {
            // There is an element in the loss list
            Some(i) => i.seq_num,
            // No elements, use lrsn + 1, as it's exclusive
            None => self.lrsn + 1,
        };

        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if ack_number == {
            let (_, a) = self.lr_ack_acked;
            a
        } {
            // stop (do not send this ACK).
            return Ok(());
        }
        if let Some(&AckHistoryEntry {
            ack_number: last_ack_number,
            timestamp: last_timestamp,
            ..
        }) = self.ack_history_window.first()
        {
            // or, (b) it is equal to the ACK number in the
            // last ACK
            if last_ack_number == ack_number &&
                    // and the time interval between this two ACK packets is
                    // less than 2 RTTs,
                    (self.get_timestamp() - last_timestamp) < (self.rtt * 2)
            {
                // stop (do not send this ACK).
                return Ok(());
            }
        }

        // 3) Assign this ACK a unique increasing ACK sequence number.
        let ack_seq_num = self.next_ack;
        self.next_ack += 1;

        // 4) Calculate the packet arrival speed according to the following
        // algorithm:
        let packet_recv_rate = {
            if self.packet_history_window.len() < 16 {
                0
            } else {
                // Calculate the median value of the last 16 packet arrival
                // intervals (AI) using the values stored in PKT History Window.
                let mut last_16: Vec<_> = self.packet_history_window
                    [self.packet_history_window.len() - 16..]
                    .iter()
                    .map(|&(_, ts)| ts)
                    .collect();
                last_16.sort();
                let ai = last_16[last_16.len() / 2];

                // In these 16 values, remove those either greater than AI*8 or
                // less than AI/8.
                let filtered: Vec<i32> = last_16
                    .iter()
                    .filter(|&&n| n < ai * 8 && n > ai / 8)
                    .cloned()
                    .collect();

                // If more than 8 values are left, calculate the
                // average of the left values AI', and the packet arrival speed is
                // 1/AI' (number of packets per second). Otherwise, return 0.
                if filtered.len() > 8 {
                    filtered.iter().sum::<i32>() / filtered.len() as i32
                } else {
                    0
                }
            }
        };

        // 5) Calculate the estimated link capacity according to the following algorithm:
        let est_link_cap = {
            if self.packet_pair_window.len() < 16 {
                0
            } else {
                //  Calculate the median value of the last 16 packet pair
                //  intervals (PI) using the values in Packet Pair Window, and the
                //  link capacity is 1/PI (number of packets per second).
                let mut last_16: Vec<_> = self.packet_pair_window
                    [self.packet_pair_window.len() - 16..]
                    .iter()
                    .map(|&(_, time)| time)
                    .collect();
                last_16.sort();
                let pi = last_16[last_16.len() / 2];

                // Multiply by 1M because pi is in microseconds
                (1.0e6 / (pi as f32)) as i32
            }
        };

        // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
        // receiver buffer size).
        let ack = self.make_control_packet(ControlTypes::Ack(
            ack_seq_num,
            AckControlInfo {
                ack_number,
                rtt: Some(self.rtt),
                rtt_variance: Some(self.rtt_variance),
                buffer_available: None, // TODO: add this
                packet_recv_rate: Some(packet_recv_rate),
                est_link_cap: Some(est_link_cap),
            },
        ));

        // add it to the ack history
        let now = self.get_timestamp();
        self.ack_history_window.push(AckHistoryEntry {
            ack_number,
            ack_seq_num,
            timestamp: now,
        });
        self.sock.start_send((ack, self.remote))?;

        Ok(())
    }

    fn on_nak_event(&mut self) -> Result<()> {
        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.

        let now = self.get_timestamp();

        // increment k and change feedback time, returning sequence numbers
        let seq_nums = {
            let mut ret = Vec::new();

            let rtt = self.rtt;
            for pak in self.loss_list
                .iter_mut()
                .filter(|lle| lle.feedback_time > now - lle.k * rtt)
            {
                pak.k += 1;
                pak.feedback_time = now;

                ret.push(pak.seq_num);
            }

            ret
        };

        if seq_nums.is_empty() {
            return Ok(());
        }

        // send the nak
        self.send_nak(seq_nums.into_iter())?;

        Ok(())
    }

    // checks the timers
    // if a timer was triggered, then an RSFutureTimeout will be returned
    // if not, the socket is given back
    fn check_timers(&mut self) -> Result<()> {
        // see if we need to ACK
        // early return if the timer isn't triggered
        match self.ack_interval.poll() {
            Err(e) => panic!(e),
            Ok(Async::NotReady) => return Ok(()),
            Ok(Async::Ready(_)) => {}
        }

        self.on_ack_event()?;

        // TODO: does this get it's own timer?
        self.on_nak_event()?;

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
                    ControlTypes::Ack(_, _) => warn!("Receiver received ACK packet, unusual"),
                    ControlTypes::Ack2(seq_num) => {
                        // 1) Locate the related ACK in the ACK History Window according to the
                        //    ACK sequence number in this ACK2.
                        let id_in_wnd = match self.ack_history_window
                            .as_slice()
                            .binary_search_by(|entry| entry.ack_seq_num.cmp(&seq_num))
                        {
                            Ok(i) => Some(i),
                            Err(_) => None,
                        };

                        if let Some(id) = id_in_wnd {
                            let AckHistoryEntry {
                                timestamp: send_timestamp,
                                ack_number,
                                ..
                            } = self.ack_history_window[id];

                            // 2) Update the largest ACK number ever been acknowledged.
                            self.lr_ack_acked = (seq_num, ack_number);

                            // 3) Calculate new rtt according to the ACK2 arrival time and the ACK
                            //    departure time, and update the RTT value as: RTT = (RTT * 7 +
                            //    rtt) / 8
                            let immediate_rtt = self.get_timestamp() - send_timestamp;
                            self.rtt = (self.rtt * 7 + immediate_rtt) / 8;

                            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
                            self.rtt_variance = (self.rtt_variance * 3
                                + (self.rtt_variance - immediate_rtt).abs())
                                / 4;

                            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                            self.ack_interval = Interval::new(Duration::new(
                                0,
                                // convert to nanoseconds
                                (4 * self.rtt + self.rtt_variance/* TODO: + syn */) as u32 * 1_000,
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
                        let sockid = self.local_sockid;

                        let ts = self.get_timestamp();
                        self.sock.start_send((
                            Packet::Control {
                                timestamp: ts,
                                dest_sockid: info.socket_id, // this is different, so don't use make_control_packet
                                control_type: ControlTypes::Handshake({
                                    let mut tmp = info;
                                    tmp.socket_id = sockid;
                                    tmp
                                }),
                            },
                            *from,
                        ))?;
                    }
                    ControlTypes::KeepAlive => {} // TODO: actually reset EXP etc
                    ControlTypes::Nak(_info) => warn!("Receiver received NAK packet, unusual"),
                    ControlTypes::Shutdown => return Ok(Some(ReadyType::Shutdown)), // end of stream
                }
            }
            Packet::Data {
                seq_number,
                payload,
                ..
            } => {
                let now = self.get_timestamp();

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
                    let first_to_be_nak = self.lrsn;
                    for i in first_to_be_nak..seq_number {
                        self.loss_list.push(LossListEntry {
                            seq_num: i,
                            feedback_time: now,
                            // k is initalized at 2, as stated on page 12 (very end)
                            k: 2,
                        })
                    }

                    self.send_nak(first_to_be_nak..seq_number)?;

                // b. If the sequence number is less than LRSN, remove it from the
                //    receiver's loss list.
                } else if seq_number < self.lrsn {
                    match self.loss_list[..].binary_search_by(|ll| ll.seq_num.cmp(&seq_number)) {
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
    fn send_nak<I>(&mut self, lost_seq_nums: I) -> Result<()>
    where
        I: Iterator<Item = i32>,
    {
        info!("Sending NAK");

        let pack = self.make_control_packet(ControlTypes::Nak(NakControlInfo {
            loss_info: compress_loss_list(lost_seq_nums).collect(),
        }));

        self.sock.start_send((pack, self.remote))?;

        Ok(())
    }

    fn make_control_packet(&self, control_type: ControlTypes) -> Packet {
        Packet::Control {
            timestamp: self.get_timestamp(),
            dest_sockid: self.remote_sockid,
            control_type,
        }
    }

    /// Timestamp in us
    fn get_timestamp(&self) -> i32 {
        let elapsed = self.sock_start_time.elapsed();

        (elapsed.as_secs() * 1_000_000 + (u64::from(elapsed.subsec_nanos()) / 1_000)) as i32
    }
}

impl<T> Stream for Receiver<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
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
