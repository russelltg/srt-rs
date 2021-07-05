use std::cmp::max;
use std::cmp::{min, Ordering};
use std::collections::VecDeque;
use std::iter::Iterator;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use log::{debug, error, info, trace, warn};

use super::TimeSpan;
use crate::packet::{
    AckControlInfo, CompressedLossList, ControlPacket, ControlTypes, DataEncryption, DataPacket,
    FullAckSeqNumber, Packet,
};
use crate::protocol::handshake::Handshake;
use crate::protocol::{TimeBase, TimeStamp};
use crate::{seq_number::seq_num_range, ConnectionSettings, SeqNumber};

mod buffer;
mod time;

use crate::connection::ConnectionStatus;
use buffer::RecvBuffer;
use time::{ReceiveTimers, Rtt};

const LIGHT_ACK_PACKET_INTERVAL: u32 = 64;

#[derive(Debug)]
struct LossListEntry {
    seq_num: SeqNumber,

    // last time it was feed into NAK
    feedback_time: Instant,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

#[derive(Clone, Debug)]
struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: SeqNumber,

    /// the ack sequence number
    ack_seq_num: Option<FullAckSeqNumber>,

    departure_time: Instant,
}

#[derive(Clone, Debug)]
struct PacketHistoryEntry {
    seqno: SeqNumber,
    time: Instant,
    size: u64, // size of payload
}

#[derive(Debug)]
pub struct Receiver {
    settings: ConnectionSettings,

    handshake: Handshake,

    timers: ReceiveTimers,

    time_base: TimeBase,

    control_packets: VecDeque<Packet>,

    data_release: VecDeque<(Instant, Bytes)>,

    /// the round trip time
    /// is calculated each ACK2
    rtt: Rtt,

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
    packet_history_window: Vec<PacketHistoryEntry>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Packet Pair Window: A circular array that records the time
    /// interval between each probing packet pair.
    ///
    /// First is seq num, second is time
    packet_pair_window: Vec<(SeqNumber, TimeSpan)>,

    /// the highest received packet sequence number + 1
    lrsn: SeqNumber,

    /// The ID of the next ack packet
    next_ack: FullAckSeqNumber,

    /// The timestamp of the probe time
    /// Used to see duration between packets
    probe_time: Option<Instant>,

    /// The ACK number from the largest ACK2
    lr_ack_acked: SeqNumber,

    /// The buffer
    receive_buffer: RecvBuffer,

    status: ConnectionStatus,
}

impl Receiver {
    pub fn new(settings: ConnectionSettings, handshake: Handshake) -> Self {
        let init_seq_num = settings.init_seq_num;

        info!(
            "Receiving started from {:?}, with latency={:?}",
            settings.remote, settings.recv_tsbpd_latency
        );

        Receiver {
            settings: settings.clone(),
            timers: ReceiveTimers::new(settings.socket_start_time),
            time_base: TimeBase::new(settings.socket_start_time),
            control_packets: VecDeque::new(),
            data_release: VecDeque::new(),
            handshake,
            rtt: Rtt::new(),
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            packet_history_window: Vec::new(),
            packet_pair_window: Vec::new(),
            lrsn: init_seq_num, // at start, we have received everything until the first packet, exclusive (aka nothing)
            next_ack: FullAckSeqNumber::INITIAL,
            probe_time: None,
            lr_ack_acked: init_seq_num,
            receive_buffer: RecvBuffer::with(&settings),
            status: ConnectionStatus::Open(settings.recv_tsbpd_latency),
        }
    }
    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }

    pub fn is_flushed(&self) -> bool {
        debug!(
            "{:?}|{:?}|recv - {:?}:{},{}",
            TimeSpan::from_interval(self.settings.socket_start_time, Instant::now()),
            self.settings.local_sockid,
            self.receive_buffer.next_msg_ready(),
            self.lr_ack_acked,
            self.receive_buffer.next_release()
        );

        self.receive_buffer.next_msg_ready().is_none()
            && self.lr_ack_acked == self.receive_buffer.next_release() // packets have been acked and all acks have been acked (ack2)
            && self.control_packets.is_empty()
            && self.data_release.is_empty()
    }

    pub fn check_timers(&mut self, now: Instant) {
        //   Data Sending Algorithm:
        //   1) Query the system time to check if ACK, NAK, or EXP timer has
        //      expired. If there is any, process the event (as described below
        //      in this section) and reset the associated time variables. For
        //      ACK, also check the ACK packet interval.
        if self.timers.check_full_ack(now).is_some() {
            self.on_full_ack_event(now);
        }
        if self.timers.check_nak(now).is_some() {
            self.on_nak_event(now);
        }
        if self.timers.check_peer_idle_timeout(now).is_some() {
            self.on_peer_idle_timeout(now);
        }
        if self.status.check_close_timeout(now, self.is_flushed()) {
            debug!("{:?} receiver close timed out", self.settings.local_sockid);
            // receiver is closing, there is no need to track ACKs anymore
            self.lr_ack_acked = self.receive_buffer.next_release()
        }
    }

    pub fn handle_shutdown_packet(&mut self, now: Instant) {
        info!(
            "{:?}: Shutdown packet received, flushing receiver...",
            self.settings.local_sockid
        );
        self.status.drain(now);
    }

    pub fn reset_exp(&mut self, now: Instant) {
        self.timers.reset_exp(now);
    }

    pub fn synchronize_clock(&mut self, now: Instant, ts: TimeStamp) {
        self.receive_buffer.synchronize_clock(now, ts)
    }

    fn caclculate_receive_rates(&mut self) -> (u32, u32) {
        if self.packet_history_window.len() < 16 {
            (0, 0)
        } else {
            // Calculate the median value of the last 16 packet arrival
            // intervals (AI) using the values stored in PKT History Window.
            let mut last_16: Vec<_> = self.packet_history_window
                [self.packet_history_window.len() - 16..]
                .windows(2)
                .map(|w| (TimeSpan::from_interval(w[0].time, w[1].time), w[0].size)) // delta time, size. Arbitrarily choose the first one
                .collect();

            self.packet_history_window =
                self.packet_history_window[self.packet_history_window.len() - 16..].to_vec();

            // the median AI
            let ai = last_16
                .select_nth_unstable_by_key(16 / 2, |k| k.0)
                .1 // get median
                 .0; // get interval

            // In these 16 values, remove those either greater than AI*8 or
            // less than AI/8.
            let filtered: Vec<_> = last_16
                .iter()
                .filter(|&&(interval, _)| interval / 8 < ai && interval > ai / 8)
                .cloned()
                .collect();

            // If more than 8 values are left, calculate the
            // average of the left values AI', and the packet arrival speed is
            // 1/AI' (number of packets per second). Otherwise, return 0.
            if filtered.len() > 8 {
                let sum_us = filtered
                    .iter()
                    .map(|(dt, _)| i64::from(dt.as_micros()))
                    .sum::<i64>() as u64; // all these dts are guaranteed to be positive

                let sum_bytes: u64 = filtered.iter().map(|(_, size)| size).sum();

                // 1e6 / (sum / len) = len * 1e6 / sum
                let rr_packets = (1_000_000 * filtered.len()) as u64 / sum_us;

                // 1e6 / (sum / bytes) = bytes * 1e6 / sum
                let rr_bytes = sum_bytes * 1_000_000 / sum_us;

                (rr_packets as u32, rr_bytes as u32)
            } else {
                (0, 0)
            }
        }
    }

    // Greatest seq number that everything before it has been received + 1
    fn ack_number(&self) -> SeqNumber {
        match self.loss_list.first() {
            // There is an element in the loss list
            Some(i) => i.seq_num,
            // No elements, use lrsn, as it's already exclusive
            None => self.lrsn,
        }
    }

    // The most recent ack number, or init seq number otherwise
    fn last_ack_number(&self) -> SeqNumber {
        if let Some(he) = self.ack_history_window.last() {
            he.ack_number
        } else {
            self.settings.init_seq_num
        }
    }

    fn full_ack_timer_active(&self) -> bool {
        self.ack_number() != self.lr_ack_acked
    }

    fn on_full_ack_event(&mut self, now: Instant) {
        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if !self.full_ack_timer_active() {
            return;
        }

        trace!("Ack event hit {:?}", self.settings.local_sockid);

        let ack_number = self.ack_number();

        // make sure this ACK number is greater or equal to a one sent previously
        assert!(self.last_ack_number() <= ack_number);

        trace!(
            "Sending ACK; ack_num={:?}, lr_ack_acked={:?}",
            ack_number,
            self.lr_ack_acked
        );

        if let Some(&AckHistoryEntry {
            ack_number: last_ack_number,
            departure_time: last_departure_time,
            ..
        }) = self.ack_history_window.first()
        {
            // or, (b) it is equal to the ACK number in the
            // last ACK
            if ack_number == last_ack_number {
                // and the time interval between these two ACK packets is
                // less than 2 RTTs,
                let interval = TimeSpan::from_interval(last_departure_time, now);
                if interval < self.rtt.mean() * 2 {
                    // stop (do not send this ACK).
                    return;
                }
            }
        }

        // 3) Assign this ACK a unique increasing ACK sequence number.
        let full_ack_seq_number = self.next_ack;
        self.next_ack.increment();

        // 4) Calculate the packet arrival speed according to the following
        // algorithm:
        let (rr_packets, rr_bytes) = self.caclculate_receive_rates();

        // 5) Calculate the estimated link capacity according to the following algorithm:
        let est_link_cap = if self.packet_pair_window.len() < 16 {
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
                last_16.sort_unstable();

                last_16[last_16.len() / 2]
            };

            self.packet_pair_window =
                self.packet_pair_window[self.packet_pair_window.len() - 16..].to_vec();

            (1. / (pi.as_secs_f64())) as u32
        };

        // Pack the ACK packet with RTT, RTT Variance, and flow window size (available
        // receiver buffer size).

        self.send_control(
            now,
            ControlTypes::Ack(AckControlInfo::FullSmall {
                ack_number,
                rtt: self.rtt.mean(),
                rtt_variance: self.rtt.variance(),
                buffer_available: 100, // TODO: add this
                full_ack_seq_number: Some(full_ack_seq_number),
                packet_recv_rate: Some(rr_packets),
                est_link_cap: Some(est_link_cap),
                data_recv_rate: Some(rr_bytes),
            }),
        );

        // add it to the ack history
        self.ack_history_window.push(AckHistoryEntry {
            ack_number,
            ack_seq_num: Some(full_ack_seq_number),
            departure_time: now,
        });
    }

    fn nak_timer_active(&self) -> bool {
        true // TODO: can this be conditioned on anything?
    }

    fn on_nak_event(&mut self, now: Instant) {
        // reset NAK timer, rtt and variance are in us, so convert to ns

        // NAK is used to trigger a negative acknowledgement (NAK). Its period
        // is dynamically updated to 4 * RTT_+ RTTVar + SYN, where RTTVar is the
        // variance of RTT samples.
        self.timers.update_rtt(&self.rtt);

        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.

        // increment k and change feedback time, returning sequence numbers
        let seq_nums = {
            let mut ret = Vec::new();

            let rtt = self.rtt.mean();
            for pak in self
                .loss_list
                .iter_mut()
                .filter(|lle| TimeSpan::from_interval(lle.feedback_time, now) > rtt * lle.k)
            {
                pak.k += 1;
                pak.feedback_time = now;

                ret.push(pak.seq_num);
            }

            ret
        };

        if seq_nums.is_empty() {
            return;
        }

        // send the nak
        self.send_nak(now, seq_nums.into_iter());
    }

    fn on_peer_idle_timeout(&mut self, now: Instant) {
        self.status.drain(now);
        self.send_control(now, ControlTypes::Shutdown);
    }
    pub fn handle_ack2_packet(&mut self, seq_num: FullAckSeqNumber, ack2_arrival_time: Instant) {
        // 1) Locate the related ACK in the ACK History Window according to the
        //    ACK sequence number in this ACK2.
        let id_in_wnd = match self
            .ack_history_window
            .as_slice()
            .binary_search_by_key(&Some(seq_num), |entry| entry.ack_seq_num)
        {
            Ok(i) => Some(i),
            Err(_) => None,
        };

        if let Some(id) = id_in_wnd {
            let AckHistoryEntry {
                ack_number,
                departure_time: ack_departure_time,
                ..
            } = self.ack_history_window[id];

            // 2) Update the largest ACK number ever been acknowledged.
            self.lr_ack_acked = ack_number;

            // 3) Calculate new rtt according to the ACK2 arrival time and the ACK
            //    , and update the RTT value as: RTT = (RTT * 7 +
            //    rtt) / 8
            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
            self.rtt.update(TimeSpan::from_interval(
                ack_departure_time,
                ack2_arrival_time,
            ));

            // 5) Update both ACK and NAK period to 4 * RTT + RTTVar + SYN.
            self.timers.update_rtt(&self.rtt);
            self.ack_history_window = self.ack_history_window[id..].to_vec();
        } else {
            warn!(
                "ACK sequence number in ACK2 packet not found in ACK history: {:?}",
                seq_num
            );
        }
    }

    pub fn handle_data_packet(&mut self, mut data: DataPacket, now: Instant) {
        // 2&3 don't apply

        // 4) If the sequence number of the current data packet is 16n + 1,
        //     where n is an integer, record the time interval between this
        if data.seq_number % 16 == 0 {
            self.probe_time = Some(now)
        } else if data.seq_number % 16 == 1 {
            // if there is an entry
            if let Some(pt) = self.probe_time {
                // calculate and insert
                let interval = TimeSpan::from_interval(pt, now);
                self.packet_pair_window.push((data.seq_number, interval));

                // reset
                self.probe_time = None
            }
        }

        // 5) Record the packet arrival time in PKT History Window.
        self.packet_history_window.push(PacketHistoryEntry {
            seqno: data.seq_number,
            time: now,
            size: data.payload.len() as u64,
        });

        // 6)
        // a. If the sequence number of the current data packet is greater
        //    than LRSN, put all the sequence numbers between (but
        //    excluding) these two values into the receiver's loss list and
        //    send them to the sender in an NAK packet.
        match data.seq_number.cmp(&self.lrsn) {
            Ordering::Greater => {
                // lrsn is the latest packet received, so nak the one after that
                for i in seq_num_range(self.lrsn, data.seq_number) {
                    self.loss_list.push(LossListEntry {
                        seq_num: i,
                        feedback_time: now,
                        // k is initialized at 2, as stated on page 12 (very end)
                        k: 2,
                    })
                }

                self.send_nak(now, seq_num_range(self.lrsn, data.seq_number));
            }
            // b. If the sequence number is less than LRSN, remove it from the
            //    receiver's loss list.
            Ordering::Less => {
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
            Ordering::Equal => {}
        }

        // record that we got this packet
        self.lrsn = max(data.seq_number + 1, self.lrsn);

        // we've already gotten this packet, drop it
        if self.receive_buffer.next_release() > data.seq_number {
            debug!("Received packet {:?} twice", data.seq_number);
            return;
        }

        // decrypt the packet if it's encrypted
        if data.encryption != DataEncryption::None {
            self.decrypt_packet(&mut data);
        }

        self.receive_buffer.add(data);

        // check if we need to send a light ACK
        if self.ack_number() - self.last_ack_number() > LIGHT_ACK_PACKET_INTERVAL {
            // send a light ack
            self.send_light_ack(now);
        }
    }

    fn send_light_ack(&mut self, now: Instant) {
        self.send_control(
            now,
            ControlTypes::Ack(AckControlInfo::Lite(self.ack_number())),
        );
        self.ack_history_window.push(AckHistoryEntry {
            ack_number: self.ack_number(),
            ack_seq_num: None,
            departure_time: now,
        });
    }

    fn decrypt_packet(&self, data: &mut DataPacket) {
        let cm = match &self.settings.crypto_manager {
            None => {
                error!("Unexpcted encrypted packet!");
                return;
            }
            Some(cm) => cm,
        };

        // this requies an extra copy here...maybe DataPacket should have a BytesMut in it instead...
        let mut bm = BytesMut::with_capacity(data.payload.len());
        bm.extend_from_slice(&data.payload[..]);
        cm.decrypt(data.seq_number, data.encryption, &mut bm);

        data.payload = bm.freeze();
    }

    // send a NAK, and return the future
    fn send_nak(&mut self, now: Instant, lost_seq_nums: impl Iterator<Item = SeqNumber>) {
        self.send_control(
            now,
            ControlTypes::Nak(CompressedLossList::from_loss_list(lost_seq_nums)),
        );
    }

    pub fn next_data(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        // try to release packets
        while let Some(d) = self.receive_buffer.next_msg_tsbpd(now) {
            self.data_release.push_back(d);
        }

        // drop packets
        // TODO: do something with this
        let _dropped = self.receive_buffer.drop_too_late_packets(now);

        self.data_release.pop_front()
    }

    pub fn next_packet(&mut self) -> Option<(Packet, SocketAddr)> {
        self.control_packets
            .pop_front()
            .map(|packet| (packet, self.settings.remote))
    }

    pub fn next_timer(&self, now: Instant) -> Instant {
        let next_timer =
            self.timers
                .next_timer(now, self.nak_timer_active(), self.full_ack_timer_active());

        match self.receive_buffer.next_message_release_time() {
            Some(next_rel_time) => max(min(next_timer, next_rel_time), now),
            None => next_timer,
        }
    }

    fn send_control(&mut self, now: Instant, control: ControlTypes) {
        self.control_packets
            .push_back(Packet::Control(ControlPacket {
                timestamp: self.time_base.timestamp_from(now),
                dest_sockid: self.settings.remote_sockid,
                control_type: control,
            }));
    }
}
