use bytes::{Bytes, BytesMut};
use failure::Error;
use futures::prelude::*;
use futures_timer::{Delay, Interval};

use {
    loss_compression::compress_loss_list,
    packet::{ControlPacket, ControlTypes, DataPacket, Packet, PacketLocation},
    seq_number::seq_num_range, srt_packet::{SrtControlPacket, SrtHandshake, SrtShakeFlags},
    srt_version, ConnectionSettings, SeqNumber,
};

use std::{
    cmp, collections::VecDeque, io::Cursor, iter::Iterator, net::SocketAddr,
    time::{Duration, Instant},
};

struct LossListEntry {
    seq_num: SeqNumber,

    // last time it was feed into NAK
    feedback_time: i32,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: SeqNumber,

    /// the ack sequence number
    ack_seq_num: i32,

    /// timestamp that it was sent at
    timestamp: i32,
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
    packet_history_window: Vec<(SeqNumber, i32)>,

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
    probe_time: Option<i32>,

    timeout_timer: Delay,

    /// The ACK sequence number of the largest ACK2 received, and the ack number
    lr_ack_acked: (i32, SeqNumber),

    /// Receive buffer
    /// Used to store packets that were received out of order
    /// In ascending sequence numbers
    /// There are no gaps between sequence nubmers
    /// the index of sequence number i is at buffer[i - last_released - 1]
    /// The instant is the estimated send time, calculated as recv_time - rtt / 2
    buffer: VecDeque<Option<(Instant, DataPacket)>>,

    /// the latest released sequence number
    last_released: SeqNumber,

    /// The TSBPD time
    /// If this is None, TSBPD is disabled
    tsbpd: Option<Duration>,
}

impl<T> Receiver<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(sock: T, settings: ConnectionSettings) -> Receiver<T> {
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
            lrsn: settings.init_seq_num - 1,
            next_ack: 1,
            exp_count: 1,
            probe_time: None,
            timeout_timer: Delay::new(Duration::from_secs(1)),
            lr_ack_acked: (0, settings.init_seq_num),
            buffer: VecDeque::new(),
            last_released: settings.init_seq_num - 1,
            tsbpd: None,
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
            // No elements, use lrsn + 1, as it's exclusive
            None => self.lrsn + 1,
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

                // the median timestamp
                let ai = last_16[last_16.len() / 2];

                // In these 16 values, remove those either greater than AI*8 or
                // less than AI/8.
                let filtered: Vec<i32> = last_16
                    .iter()
                    .filter(|&&n| n / 8 < ai && n > ai / 8)
                    .cloned()
                    .collect();

                // If more than 8 values are left, calculate the
                // average of the left values AI', and the packet arrival speed is
                // 1/AI' (number of packets per second). Otherwise, return 0.
                if filtered.len() > 8 {
                    (filtered.iter().fold(0i64, |sum, &val| sum + val as i64)
                        / filtered.len() as i64) as i32
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
        debug!("Sending ACK packet for {}", ack_number);
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
        let now = self.get_timestamp();
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
        self.nak_interval.reset(Duration::new(
            nak_interval_us / 1_000_000,
            (nak_interval_us % 1_000_000) as u32 * 1_000,
        ));

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
            for pak in self
                .loss_list
                .iter_mut()
                .filter(|lle| lle.feedback_time < now - lle.k * rtt)
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

        Ok(())
    }

    // gets the id in `buffer` of a given sequence number
    fn id_in_buffer(&self, seq: SeqNumber) -> usize {
        assert!(self.last_released < seq);

        (seq - self.last_released - 1) as usize
    }

    // handles a SRT control packet
    fn handle_srt_control_packet(&mut self, pack: SrtControlPacket) -> Result<(), Error> {
        match pack {
            SrtControlPacket::HandshakeRequest(shake) => {
                // make sure the SRT version matches ours
                if srt_version::CURRENT != shake.version {
                    bail!(
                        "Incomatible version, local is {}, remote is {}",
                        srt_version::CURRENT,
                        shake.version
                    );
                }

                // make sure it's a sender, cuz otherwise we have a problem
                if shake.flags.contains(SrtShakeFlags::TSBPDRCV) {
                    bail!("Receiver tried to connect with another receiver, aborting.");
                }

                // make sure the sender flag is set, or else neither sender nor recv are set, which is bad
                if !shake.flags.contains(SrtShakeFlags::TSBPDSND) {
                    bail!(
                        "Got SRT handshake packet with neither receiver or sender set. Flags={:#b}",
                        shake.flags.bits()
                    );
                }

                self.tsbpd = Some(Duration::max(
                    self.settings
                        .tsbpd_latency
                        .unwrap_or(Duration::from_millis(0)), // if we never specified TSBPD, just use the sender's
                    shake.latency,
                ));

                info!(
                    "Got SRT handshake, using TSBPD={}ms",
                    self.tsbpd.unwrap().as_secs() * 1_000
                        + self.tsbpd.unwrap().subsec_nanos() as u64 / 1_000
                );

                // return the response
                let mut bytes = BytesMut::new();
                let reserved = SrtControlPacket::HandshakeResponse(SrtHandshake {
                    version: srt_version::CURRENT,
                    flags: SrtShakeFlags::TSBPDRCV, // TODO: the reference implementation sets a lot more of these, research
                    latency: self.tsbpd.unwrap(),
                }).serialize(&mut bytes);

                let pack = self.make_control_packet(ControlTypes::Custom {
                    custom_type: reserved,
                    control_info: bytes.freeze(),
                });
                self.sock.start_send((pack, self.settings.remote))?;
            }
            SrtControlPacket::HandshakeResponse(_) => {
                warn!("Receiver received SRT handshake response, unusual.")
            }
        }

        Ok(())
    }

    // handles an incomming a packet, returning if it was a shutdown packet and the socket should close
    fn handle_packet(&mut self, packet: Packet, from: &SocketAddr) -> Result<bool, Error> {
        // We don't care about packets from elsewhere
        if *from != self.settings.remote {
            info!("Packet received from unknown address: {:?}", from);
            return Ok(false);
        }

        trace!("Received packet: {:?}", packet);

        match packet {
            Packet::Control(ctrl) => {
                // handle the control packet

                if self.settings.local_sockid != ctrl.dest_sockid {
                    // packet isn't applicable
                    return Ok(false);
                }

                match ctrl.control_type {
                    ControlTypes::Ack { .. } => warn!("Receiver received ACK packet, unusual"),
                    ControlTypes::Ack2(seq_num) => {
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
                            let immediate_rtt = self.get_timestamp() - send_timestamp;
                            self.rtt = (self.rtt * 7 + immediate_rtt) / 8;

                            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
                            self.rtt_variance = (self.rtt_variance * 3
                                + (self.rtt_variance - immediate_rtt).abs())
                                / 4;

                            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
                            let ack_us = 4 * self.rtt as u64 + self.rtt_variance as u64 + 10_000;
                            self.ack_interval = Interval::new(Duration::new(
                                ack_us / 1_000_000,
                                ((ack_us % 1_000_000) * 1_000) as u32,
                            ));
                        } else {
                            warn!(
                                "ACK sequence number in ACK2 packet not found in ACK history: {}",
                                seq_num
                            );
                        }
                    }
                    ControlTypes::DropRequest { .. } => unimplemented!(),
                    ControlTypes::Handshake(info) => {
                        // just send it back
                        let sockid = self.settings.local_sockid;

                        let ts = self.get_timestamp();
                        self.sock.start_send((
                            Packet::Control(ControlPacket {
                                timestamp: ts,
                                dest_sockid: info.socket_id, // this is different, so don't use make_control_packet
                                control_type: ControlTypes::Handshake({
                                    let mut tmp = info;
                                    tmp.socket_id = sockid;
                                    tmp
                                }),
                            }),
                            *from,
                        ))?;
                    }
                    ControlTypes::KeepAlive => {} // TODO: actually reset EXP etc
                    ControlTypes::Nak { .. } => warn!("Receiver received NAK packet, unusual"),
                    ControlTypes::Shutdown => return Ok(true), // end of stream
                    ControlTypes::Custom {
                        custom_type,
                        control_info,
                    } => {
                        // decode srt packet
                        let srt_packet =
                            SrtControlPacket::parse(custom_type, &mut Cursor::new(control_info))?;

                        self.handle_srt_control_packet(srt_packet)?;
                    }
                }
            }
            Packet::Data(data) => {
                debug!("Received data packet seq_num={}", data.seq_number);

                let now = self.get_timestamp();

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
                        self.packet_pair_window.push((data.seq_number, now - pt));

                        // reset
                        self.probe_time = None;
                    }
                }
                // 5) Record the packet arrival time in PKT History Window.
                self.packet_history_window.push((data.seq_number, now));

                // 6)
                // a. If the sequence number of the current data packet is greater
                //    than LRSN + 1, put all the sequence numbers between (but
                //    excluding) these two values into the receiver's loss list and
                //    send them to the sender in an NAK packet.
                if data.seq_number > self.lrsn + 1 {
                    // lrsn is the latest packet received, so nak the one after that
                    let first_to_be_nak = self.lrsn + 1;
                    for i in seq_num_range(first_to_be_nak, data.seq_number) {
                        self.loss_list.push(LossListEntry {
                            seq_num: i,
                            feedback_time: now,
                            // k is initialized at 2, as stated on page 12 (very end)
                            k: 2,
                        })
                    }

                    self.send_nak(seq_num_range(first_to_be_nak, data.seq_number))?;

                // b. If the sequence number is less than LRSN, remove it from the
                //    receiver's loss list.
                } else if data.seq_number < self.lrsn {
                    match self.loss_list[..].binary_search_by(|ll| ll.seq_num.cmp(&data.seq_number))
                    {
                        Ok(i) => {
                            self.loss_list.remove(i);
                            ()
                        }
                        Err(_) => {
                            warn!(
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
                self.lrsn = cmp::max(data.seq_number, self.lrsn);

                // we've already gotten this packet, drop it
                if self.last_released >= data.seq_number {
                    warn!("Received packet {:?} twice", data.seq_number);
                    return Ok(false);
                }

                // add it to the buffer at the right spot
                // keep it sorted ascending

                // make sure the buffer is big enough
                // this cast is safe because last_released is garunteed to be >= seq_number
                let seq_id_in_buffer = self.id_in_buffer(data.seq_number);
                if seq_id_in_buffer >= self.buffer.len() {
                    self.buffer.resize(seq_id_in_buffer + 1, None);
                }

                // add it the buffer
                if self.buffer[seq_id_in_buffer].is_some() {
                    debug!("Received packet {:?} twice", data.seq_number);
                }
                self.buffer[seq_id_in_buffer] = Some((
                    Instant::now() - Duration::new(0, self.rtt as u32 / 2 * 1_000),
                    data,
                ));

                if self.buffer.len() != 0 {
                    trace!(
                        "lr={}, buffer.len()={}, buffer[0]={}, buffer[last]={}",
                        self.last_released,
                        self.buffer.len(),
                        self.buffer[0]
                            .as_ref()
                            .map(|(_, ref p)| p.seq_number)
                            .unwrap_or(SeqNumber::new(0)),
                        self.buffer[self.buffer.len() - 1]
                            .as_ref()
                            .map(|(_, ref p)| p.seq_number)
                            .unwrap_or(SeqNumber::new(0)),
                    );
                }
            }
        };

        Ok(false)
    }

    // check if a whole message is available in buffer
    // TODO: this sort of logic should be in it's own struct--to make it easier to test. It's complex.
    fn is_message_available(&self) -> bool {
        // if data packets are ready, send them
        if let Some(&Some((_, ref packet))) = self.buffer.front() {
            assert_eq!(packet.seq_number, self.last_released + 1);

            // make sure to reconstruct messages correctly
            match packet.message_loc {
                a if a.contains(PacketLocation::FIRST | PacketLocation::LAST) => true,
                PacketLocation::FIRST => {
                    let message_number = packet.message_number;

                    // loop through the buffer, making sure they're available, skipping the first one as it's this one.
                    for packet_opt in self.buffer.iter().skip(1) {
                        if let Some((_, packet)) = packet_opt {
                            if packet.message_number != message_number {
                                warn!(
                                    "Unexpected change in messenge number, expected {} got {}",
                                    message_number, packet.message_number
                                );
                                return false; // i guess?
                            }
                            if packet.message_loc == PacketLocation::LAST {
                                return true;
                            }
                        } else {
                            return false;
                        }
                    }
                    false
                }
                _ => {
                    warn!("Unexpected middle of message (firt bit not set), expected first. This probably indicates a bug in the sender.");

                    false
                }
            }
        } else {
            false
        }
    }

    // reconstruct the next, removing it from the buffer
    // panics if `is_message_availabe()` returns false
    fn pop_front_msg(&mut self) -> Bytes {
        let (_, first) = self.buffer.pop_front().unwrap().unwrap();

        // it's a one packet message, just return the payload from it
        if first
            .message_loc
            .contains(PacketLocation::FIRST | PacketLocation::LAST)
        {
            return first.payload;
        }

        // reconstruct it
        let mut ret = BytesMut::new();
        loop {
            let (_, pkt) = self.buffer.pop_front().unwrap().unwrap();

            ret.extend(pkt.payload);

            if pkt.message_loc.contains(PacketLocation::LAST) {
                break ret.freeze();
            }
        }
    }

    // in non-tsbpd mode, see if there are packets to release
    fn try_release_no_tsbpd(&mut self) -> Option<Bytes> {
        if self.is_message_available() {
            Some(self.pop_front_msg())
        } else {
            None
        }
    }

    // TODO: rewrite this with `pop_front_msg`
    fn try_release_tsbpd(&mut self, tsbpd: Duration) -> Option<Bytes> {
        let first = self.buffer.pop_front()?;

        match first {
            Some((send_time, pack)) => {
                // TODO: is this right? XXX debug
                let send_time_ts = pack.timestamp;

                // if ready to release, do
                // TODO: deal with messages (yuck)
                if self.get_timestamp()
                    >= send_time_ts as i32 + {
                        tsbpd.as_secs() as u32 * 1_000_000 + tsbpd.subsec_nanos() / 1_000
                    } as i32
                {
                    self.last_released += 1;
                    Some(pack.payload)
                } else {
                    self.buffer.push_front(Some((send_time, pack))); // re-add
                    None
                }
            }
            // if the most recent packet hasn't been received yet, see if we need to discard some packets
            None => {
                // find if the first actually received packet should be released
                let time = self
                    .buffer
                    .iter()
                    .find(|ref a| a.is_some())?
                    .as_ref()?
                    .0
                    .clone();

                if Instant::now() >= time + tsbpd {
                    // drop all the missing packets
                    // unwrap is safe b/c we know there is a Some packet, as the ? above didn't return
                    while let None = self.buffer.front().unwrap() {
                        self.last_released += 1;
                        warn!(
                            "Dropping packet {}, did not arrive in time",
                            self.last_released
                        );
                        self.buffer.pop_front();
                    }
                    self.last_released += 1;
                    let payload = self.buffer
                        .pop_front()
                        .unwrap() // we know there is at least one element
                        .unwrap() // we know it is non-null, cuz the while let terminated
                        .1 // get the packet, not the time
                        .payload;

                    Some(payload)
                } else {
                    // re-add the initial packet
                    self.buffer.push_front(None);
                    None
                }
            }
        }
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
            timestamp: self.get_timestamp(),
            dest_sockid: self.settings.remote_sockid,
            control_type,
        })
    }

    /// Timestamp in us
    fn get_timestamp(&self) -> i32 {
        self.settings.get_timestamp()
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
            trace!(
                "last_rel={} Buffer={:?}",
                self.last_released,
                self.buffer
                    .iter()
                    .map(|a| a.as_ref().map(|(_, p)| p.seq_number))
                    .collect::<Vec<_>>()
            );

            // try to release packets
            match match self.tsbpd {
                Some(tsbpd) => self.try_release_tsbpd(tsbpd),
                None => self.try_release_no_tsbpd(),
            } {
                Some(p) => return Ok(Async::Ready(Some(p))),
                None => {}
            }

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

                    info!("Received shutdown, closing receiver");
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

            if res {
                return Ok(Async::Ready(None));
            }
        }
    }
}
