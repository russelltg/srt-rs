use bytes::Bytes;
use failure::Error;
use futures::prelude::*;
use futures_timer::{Delay, Interval};
use log::{debug, info, trace, warn};

use crate::loss_compression::compress_loss_list;
use crate::packet::{ControlPacket, ControlTypes, DataPacket, Packet, SrtControlPacket};
use crate::{seq_number::seq_num_range, ConnectionSettings, SeqNumber};

use std::cmp;
use std::iter::Iterator;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod buffer;
use self::buffer::RecvBuffer;

struct LossListEntry {
    seq_num: SeqNumber,

    // last time it was feed into NAK
    feedback_time: u64,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: SeqNumber,

    /// the ack sequence number
    ack_seq_num: i32,

    /// timestamp that it was sent at
    timestamp: u64,
}

pub struct Receiver<T> {
    settings: ConnectionSettings,

    /// the round trip time, in microseconds
    /// is calculated each ACK2
    rtt: i32,

    /// the round trip time variance, in microseconds
    /// is calculated each ACK2
    rtt_variance: i32,

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
    ///
    /// First is sequence number, second is timestamp
    packet_history_window: Vec<(SeqNumber, u64)>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Packet Pair Window: A circular array that records the time
    /// interval between each probing packet pair.
    ///
    /// First is seq num, second is time
    packet_pair_window: Vec<(SeqNumber, i32)>,

    /// Wakes the thread when an ACK
    ack_interval: Interval,

    /// Wakes the thread when a NAK is to be sent
    nak_interval: Delay,

    /// the highest received packet sequence number + 1
    lrsn: SeqNumber,

    /// The number of consecutive timeouts
    exp_count: i32,

    /// The ID of the next ack packet
    next_ack: i32,

    /// The timestamp of the probe time
    /// Used to see duration between packets
    probe_time: Option<u64>,

    timeout_timer: Delay,

    /// The ACK sequence number of the largest ACK2 received, and the ack number
    lr_ack_acked: (i32, SeqNumber),

    /// The buffer
    buffer: RecvBuffer,

    /// Shutdown flag. This is set so when the buffer is flushed, it returns Async::Ready(None)
    shutdown_flag: bool,

    /// Release delay
    /// wakes the thread when there is a new packet to be released
    release_delay: Delay,
}

impl<T> Receiver<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(sock: T, settings: ConnectionSettings) -> Receiver<T> {
        let init_seq_num = settings.init_seq_num;

        info!(
            "Receiving started from {:?}, with latency={:?}",
            settings.remote, settings.tsbpd_latency
        );

        Receiver {
            settings,
            sock,
            rtt: 10_000,
            rtt_variance: 1_000,
            listen_timeout: Duration::from_secs(1),
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            packet_history_window: Vec::new(),
            packet_pair_window: Vec::new(),
            ack_interval: Interval::new(Duration::from_millis(10)),
            nak_interval: Delay::new(Duration::from_millis(10)),
            lrsn: init_seq_num, // at start, we have received everything until the first packet, exclusive (aka nothing)
            next_ack: 1,
            exp_count: 1,
            probe_time: None,
            timeout_timer: Delay::new(Duration::from_secs(1)),
            lr_ack_acked: (0, init_seq_num),
            buffer: RecvBuffer::new(init_seq_num),
            shutdown_flag: false,
            release_delay: Delay::new(Duration::from_secs(0)), // start with an empty delay
        }
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    pub fn remote(&self) -> SocketAddr {
        self.settings.remote
    }

    fn reset_timeout(&mut self) {
        self.timeout_timer.reset(self.listen_timeout)
    }

    fn on_ack_event(&mut self) -> Result<(), Error> {
        // get largest inclusive received packet number
        let ack_number = match self.loss_list.first() {
            // There is an element in the loss list
            Some(i) => i.seq_num,
            // No elements, use lrsn, as it's already exclusive
            None => self.lrsn,
        };

        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if ack_number == self.lr_ack_acked.1 {
            // stop (do not send this ACK).
            return Ok(());
        }

        // make sure this ACK number is greater or equal to a one sent previously
        if let Some(w) = self.ack_history_window.last() {
            assert!(w.ack_number <= ack_number);
        }

        trace!(
            "Sending ACK; ack_num={:?}, lr_ack_acked={:?}",
            ack_number,
            self.lr_ack_acked.1
        );

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
                    ((self.get_timestamp_now() - last_timestamp) as i32) < (self.rtt * 2)
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

                // the median timestamp
                let ai = last_16[last_16.len() / 2];

                // In these 16 values, remove those either greater than AI*8 or
                // less than AI/8.
                let filtered: Vec<u64> = last_16
                    .iter()
                    .filter(|&&n| n / 8 < ai && n > ai / 8)
                    .cloned()
                    .collect();

                // If more than 8 values are left, calculate the
                // average of the left values AI', and the packet arrival speed is
                // 1/AI' (number of packets per second). Otherwise, return 0.
                if filtered.len() > 8 {
                    (filtered.iter().fold(0u64, |sum, &val| sum + val)
                        / (filtered.len() as u64)) as i32
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
                let pi = {
                    let mut last_16: Vec<_> = self.packet_pair_window
                        [self.packet_pair_window.len() - 16..]
                        .iter()
                        .map(|&(_, time)| time)
                        .collect();
                    last_16.sort();

                    last_16[last_16.len() / 2]
                };

                // Multiply by 1M because pi is in microseconds
                // pi is in us/packet
                (1.0e6 / (pi as f32)) as i32
            }
        };

        // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
        // receiver buffer size).
        debug!("Sending ACK packet for packets <{}", ack_number);
        let ack = self.make_control_packet(ControlTypes::Ack {
            ack_seq_num,
            ack_number,
            rtt: Some(self.rtt),
            rtt_variance: Some(self.rtt_variance),
            buffer_available: None, // TODO: add this
            packet_recv_rate: Some(packet_recv_rate),
            est_link_cap: Some(est_link_cap),
        });

        // add it to the ack history
        let now = self.get_timestamp_now();
        self.ack_history_window.push(AckHistoryEntry {
            ack_number,
            ack_seq_num,
            timestamp: now,
        });
        self.sock.start_send((ack, self.settings.remote))?;

        Ok(())
    }

    fn on_nak_event(&mut self) -> Result<(), Error> {
        // reset NAK timer, rtt and variance are in us, so convert to ns

        // NAK is used to trigger a negative acknowledgement (NAK). Its period
        // is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
        // variance of RTT samples.
        let nak_interval_us = 4 * self.rtt as u64 + self.rtt_variance as u64 + 10_000;
        self.nak_interval
            .reset(Duration::from_micros(nak_interval_us));

        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.

        let now = self.get_timestamp_now();

        // increment k and change feedback time, returning sequence numbers
        let seq_nums = {
            let mut ret = Vec::new();

            let rtt = self.rtt;
            for pak in self
                .loss_list
                .iter_mut()
                .filter(|lle| (now - lle.feedback_time) as i32 > lle.k * rtt)
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
    fn check_timers(&mut self) -> Result<(), Error> {
        // see if we need to ACK or NAK
        if let Async::Ready(_) = self.ack_interval.poll()? {
            self.on_ack_event()?;
        }

        if let Async::Ready(_) = self.nak_interval.poll()? {
            self.on_nak_event()?;
        }

        // no need to do anything specific
        let _ = self.release_delay.poll()?;

        Ok(())
    }

    // handles a SRT control packet
    fn handle_srt_control_packet(&mut self, pack: &SrtControlPacket) -> Result<(), Error> {
        use self::SrtControlPacket::*;

        match pack {
            HandshakeRequest(_) | HandshakeResponse(_) => {
                warn!("Received handshake SRT packet, HSv5 expected");
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    // handles an incomming a packet
    fn handle_packet(&mut self, packet: &Packet, from: &SocketAddr) -> Result<(), Error> {
        // We don't care about packets from elsewhere
        if *from != self.settings.remote {
            info!("Packet received from unknown address: {:?}", from);
            return Ok(());
        }

        if self.settings.local_sockid != packet.dest_sockid() {
            // packet isn't applicable
            info!(
                "Packet send to socket id ({}) that does not match local ({})",
                packet.dest_sockid().0,
                self.settings.local_sockid.0
            );
            return Ok(());
        }

        trace!("Received packet: {:?}", packet);

        match packet {
            Packet::Control(ctrl) => {
                // handle the control packet

                match &ctrl.control_type {
                    ControlTypes::Ack { .. } => warn!("Receiver received ACK packet, unusual"),
                    ControlTypes::Ack2(seq_num) => self.handle_ack2(*seq_num)?,
                    ControlTypes::DropRequest { .. } => unimplemented!(),
                    ControlTypes::Handshake(_) => {
                        if let Some(pack) = (*self.settings.handshake_returner)(&packet) {
                            self.sock.start_send((pack, self.settings.remote))?;
                        }
                    }
                    ControlTypes::KeepAlive => {} // TODO: actually reset EXP etc
                    ControlTypes::Nak { .. } => warn!("Receiver received NAK packet, unusual"),
                    ControlTypes::Shutdown => {
                        info!("Shutdown packet received, flushing receiver...");
                        self.shutdown_flag = true;
                    } // end of stream
                    ControlTypes::Srt(srt_packet) => {
                        self.handle_srt_control_packet(srt_packet)?;
                    }
                }
            }
            Packet::Data(data) => self.handle_data_packet(&data)?,
        };

        Ok(())
    }

    fn handle_ack2(&mut self, seq_num: i32) -> Result<(), Error> {
        // 1) Locate the related ACK in the ACK History Window according to the
        //    ACK sequence number in this ACK2.
        let id_in_wnd = match self
            .ack_history_window
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
            let immediate_rtt = (self.get_timestamp_now() - send_timestamp) as i32;
            self.rtt = (self.rtt * 7 + immediate_rtt) / 8;

            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
            self.rtt_variance =
                (self.rtt_variance * 3 + (self.rtt_variance - immediate_rtt).abs()) / 4;

            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
            let ack_us = 4 * self.rtt as u64 + self.rtt_variance as u64 + 10_000;
            self.ack_interval = Interval::new(Duration::from_micros(ack_us));
        } else {
            warn!(
                "ACK sequence number in ACK2 packet not found in ACK history: {}",
                seq_num
            );
        }

        Ok(())
    }

    fn handle_data_packet(&mut self, data: &DataPacket) -> Result<(), Error> {
        let now = self.get_timestamp_now();

        // 1) Reset the ExpCount to 1. If there is no unacknowledged data
        //     packet, or if this is an ACK or NAK control packet, reset the EXP
        //     timer.
        self.exp_count = 1;

        // 2&3 don't apply

        // 4) If the sequence number of the current data packet is 16n + 1,
        //     where n is an integer, record the time interval between this
        if data.seq_number % 16 == 0 {
            self.probe_time = Some(now)
        } else if data.seq_number % 16 == 1 {
            // if there is an entry
            if let Some(pt) = self.probe_time {
                // calculate and insert
                self.packet_pair_window.push((data.seq_number, (now - pt) as i32));

                // reset
                self.probe_time = None;
            }
        }
        // 5) Record the packet arrival time in PKT History Window.
        self.packet_history_window.push((data.seq_number, now));

        // 6)
        // a. If the sequence number of the current data packet is greater
        //    than LRSN, put all the sequence numbers between (but
        //    excluding) these two values into the receiver's loss list and
        //    send them to the sender in an NAK packet.
        if data.seq_number > self.lrsn {
            // lrsn is the latest packet received, so nak the one after that
            for i in seq_num_range(self.lrsn, data.seq_number) {
                self.loss_list.push(LossListEntry {
                    seq_num: i,
                    feedback_time: now,
                    // k is initialized at 2, as stated on page 12 (very end)
                    k: 2,
                })
            }

            self.send_nak(seq_num_range(self.lrsn, data.seq_number))?;

        // b. If the sequence number is less than LRSN, remove it from the
        //    receiver's loss list.
        } else if data.seq_number < self.lrsn {
            match self.loss_list[..].binary_search_by(|ll| ll.seq_num.cmp(&data.seq_number)) {
                Ok(i) => {
                    self.loss_list.remove(i);
                }
                Err(_) => {
                    debug!(
                        "Packet received that's not in the loss list: {:?}, loss_list={:?}",
                        data.seq_number,
                        self.loss_list
                            .iter()
                            .map(|ll| ll.seq_num.as_raw())
                            .collect::<Vec<_>>()
                    );
                }
            };
        }

        // record that we got this packet
        self.lrsn = cmp::max(data.seq_number + 1, self.lrsn);

        // we've already gotten this packet, drop it
        if self.buffer.next_release() > data.seq_number {
            debug!("Received packet {:?} twice", data.seq_number);
            return Ok(());
        }

        self.buffer.add(data.clone());

        trace!(
            "Received data packet seq_num={}, loc={:?}, buffer={:?}",
            data.seq_number,
            data.message_loc,
            self.buffer,
        );

        Ok(())
    }

    // send a NAK, and return the future
    fn send_nak<I>(&mut self, lost_seq_nums: I) -> Result<(), Error>
    where
        I: Iterator<Item = SeqNumber>,
    {
        let vec: Vec<_> = lost_seq_nums.collect();
        debug!("Sending NAK for={:?}", vec);

        let pack = self.make_control_packet(ControlTypes::Nak(
            compress_loss_list(vec.iter().cloned()).collect(),
        ));

        self.sock.start_send((pack, self.settings.remote))?;

        Ok(())
    }

    fn make_control_packet(&self, control_type: ControlTypes) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: self.get_timestamp_now() as i32,
            dest_sockid: self.settings.remote_sockid,
            control_type,
        })
    }

    /// Timestamp in us
    fn get_timestamp_now(&self) -> u64 {
        self.settings.get_timestamp_now()
    }
}

impl<T> Stream for Receiver<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    type Item = (Instant, Bytes);
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<(Instant, Bytes)>, Error> {
        self.check_timers()?;

        self.sock.poll_complete()?;

        loop {
            // try to release packets

            let tsbpd = self.settings.tsbpd_latency;

            if let Some((ts, p)) = self
                .buffer
                .next_msg_tsbpd(tsbpd, self.settings.socket_start_time)
            {
                return Ok(Async::Ready(Some((
                    self.settings.socket_start_time + Duration::from_micros(ts),
                    p,
                ))));
            }

            // drop packets
            // TODO: do something with this
            let _dropped = self
                .buffer
                .drop_too_late_packets(tsbpd, self.settings.socket_start_time);

            match self.timeout_timer.poll() {
                Err(e) => panic!(e), // why would this ever happen
                Ok(Async::Ready(_)) => {
                    self.exp_count += 1;
                    self.reset_timeout();
                }
                Ok(Async::NotReady) => {}
            }

            // if there is a packet ready, set the timeout timer for it
            if let Some(release_time) = self
                .buffer
                .next_message_release_time(self.settings.socket_start_time, tsbpd)
            {
                self.release_delay.reset_at(release_time);
            }

            // if there isn't a complete message at the beginning of the buffer and we are supposed to be shutting down, shut down
            if self.shutdown_flag && self.buffer.next_msg_ready().is_none() {
                info!("Shutdown received and all packets released, finishing up");
                return Ok(Async::Ready(None));
            }

            let (packet, addr) = match self.sock.poll() {
                Err(e) => {
                    warn!("Error reading packet: {:?}", e);

                    continue;
                }
                Ok(Async::Ready(Some(p))) => p,
                Ok(Async::Ready(None)) => {
                    // end of stream, shutdown
                    self.shutdown_flag = true;

                    continue;
                }
                // TODO: exp_count
                Ok(Async::NotReady) => return Ok(Async::NotReady),
            };

            // handle the socket
            // packet was received, reset exp_count
            self.exp_count = 1;
            self.reset_timeout();

            self.handle_packet(&packet, &addr)?;

            // TODO: should this be here for optimal performance?
            self.sock.poll_complete()?;
        }
    }
}
