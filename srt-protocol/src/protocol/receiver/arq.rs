use std::time::Instant;

use crate::packet::{AckControlInfo, CompressedLossList, FullAckSeqNumber};
use crate::protocol::receiver::time::Rtt;
use crate::protocol::TimeSpan;
use crate::seq_number::seq_num_range;
use crate::SeqNumber;
use array_init::from_iter;
use arraydeque::behavior::Wrapping;
use arraydeque::ArrayDeque;
use log::{debug, trace, warn};
use std::cmp::{max, Ordering};

#[derive(Debug)]
pub struct ArrivalSpeed {
    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// PKT History Window: A circular array that records the arrival time
    /// of each data packet.
    ///
    /// Instead of arrival time we store packet arrival intervals and data size
    /// in the PKT History Window.
    packet_history_window: ArrayDeque<[(TimeSpan, u64); 16], Wrapping>,
    last_arrival_time: Option<Instant>,
}

impl ArrivalSpeed {
    pub fn new() -> Self {
        Self {
            packet_history_window: ArrayDeque::new(),
            last_arrival_time: None,
        }
    }

    pub fn record_data_packet(&mut self, now: Instant, size: usize) {
        // Calculate the median value of the last 16 packet arrival
        // intervals (AI) using the values stored in PKT History Window.
        if let Some(last) = self.last_arrival_time {
            let interval = TimeSpan::from_interval(last, now);
            let _ = self
                .packet_history_window
                .push_back((interval, size as u64));
        }
        self.last_arrival_time = Some(now);
    }

    pub fn calculate(&self) -> Option<(u32, u32)> {
        if !self.packet_history_window.is_full() {
            return None;
        }

        let mut window: [_; 16] = from_iter(self.packet_history_window.iter()).unwrap();

        // the median AI
        let ai = window
            .select_nth_unstable_by_key(16 / 2, |k| k.0)
            .1 // get median
             .0; // get interval

        // In these 16 values, remove those either greater than AI*8 or
        // less than AI/8.
        let filtered: ArrayDeque<[_; 16]> = window
            .iter()
            .filter(|(interval, _)| *interval / 8 < ai && *interval > ai / 8)
            .collect();

        if filtered.len() <= 8 {
            return None;
        }

        // If more than 8 values are left, calculate the
        // average of the left values AI', and the packet arrival speed is
        // 1/AI' (number of packets per second). Otherwise, return 0.

        let sum_us = filtered
            .iter()
            .map(|(dt, _)| i64::from(dt.as_micros()))
            .sum::<i64>() as u64; // all these dts are guaranteed to be positive

        let sum_bytes: u64 = filtered.iter().map(|(_, size)| size).sum();

        // 1e6 / (sum / len) = len * 1e6 / sum
        let rr_packets = (1_000_000 * filtered.len()) as u64 / sum_us;

        // 1e6 / (sum / bytes) = bytes * 1e6 / sum
        let rr_bytes = sum_bytes * 1_000_000 / sum_us;

        Some((rr_packets as u32, rr_bytes as u32))
    }
}

#[derive(Debug)]
pub struct LinkCapacityEstimate {
    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Packet Pair Window: A circular array that records the time
    /// interval between each probing packet pair.
    packet_pair_window: ArrayDeque<[TimeSpan; 16], Wrapping>,
    /// The timestamp of the probe time
    /// Used to calculate duration between packets
    probe_time: Option<Instant>,
}

impl LinkCapacityEstimate {
    pub fn new() -> Self {
        Self {
            probe_time: None,
            packet_pair_window: ArrayDeque::new(),
        }
    }

    pub fn calculate(&self) -> Option<u32> {
        if !self.packet_pair_window.is_full() {
            return None;
        }

        //  Calculate the median value of the last 16 packet pair
        //  intervals (PI) using the values in Packet Pair Window, and the
        //  link capacity is 1/PI (number of packets per second).
        let window = self.packet_pair_window.iter().copied();
        let mut sorted: [TimeSpan; 16] = from_iter(window).unwrap();
        sorted.sort_unstable();
        Some((1. / (sorted[7].as_secs_f64())) as u32)
    }

    pub fn record_data_packet(&mut self, now: Instant, seq_number: SeqNumber) {
        if seq_number % 16 == 0 {
            self.probe_time = Some(now)
        } else if seq_number % 16 == 1 {
            if let Some(pt) = self.probe_time {
                let interval = TimeSpan::from_interval(pt, now);
                let _ = self.packet_pair_window.push_back(interval);
            }
            self.probe_time = None
        }
    }
}

#[derive(Debug)]
struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    ack_number: SeqNumber,

    /// the ack sequence number
    ack_seq_num: Option<FullAckSeqNumber>,

    departure_time: Instant,
}

#[derive(Debug)]
struct LossListEntry {
    seq_num: SeqNumber,

    // last time it was feed into NAK
    feedback_time: Instant,

    // the number of times this entry has been fed back into NAK
    k: i32,
}

const LIGHT_ACK_PACKET_INTERVAL: u32 = 64;

#[derive(Debug)]
pub struct AutomaticRepeatRequestAlgorithm {
    /// the round trip time
    /// is calculated each ACK2
    rtt: Rtt,

    link_capacity_estimate: LinkCapacityEstimate,
    arrival_speed: ArrivalSpeed,
    init_seq_num: SeqNumber,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// ACK History Window: A circular array of each sent ACK and the time
    /// it is sent out. The most recent value will overwrite the oldest
    /// one if no more free space in the array.
    ack_history_window: Vec<AckHistoryEntry>,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Receiver's Loss List: It is a list of tuples whose values include:
    /// the sequence numbers of detected lost data packets, the latest
    /// feedback time of each tuple, and a parameter k that is the number
    /// of times each one has been fed back in NAK. Values are stored in
    /// the increasing order of packet sequence numbers.
    loss_list: Vec<LossListEntry>,

    /// The ID of the next ack packet
    next_ack: FullAckSeqNumber,

    /// the highest received packet sequence number + 1
    lrsn: SeqNumber,

    /// The ACK number from the largest ACK2
    pub lr_ack_acked: SeqNumber,
}

impl AutomaticRepeatRequestAlgorithm {
    pub fn new(init_seq_num: SeqNumber) -> Self {
        Self {
            init_seq_num,
            link_capacity_estimate: LinkCapacityEstimate::new(),
            arrival_speed: ArrivalSpeed::new(),
            rtt: Rtt::new(),
            loss_list: Vec::new(),
            ack_history_window: Vec::new(),
            lrsn: init_seq_num, // at start, we have received everything until the first packet, exclusive (aka nothing)
            next_ack: FullAckSeqNumber::INITIAL,
            lr_ack_acked: init_seq_num,
        }
    }

    pub fn on_full_ack_event(&mut self, now: Instant) -> Option<AckControlInfo> {
        let ack_number = self.ack_number();

        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if ack_number == self.lr_ack_acked {
            return None;
        }

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
                    return None;
                }
            }
        }

        // 3) Assign this ACK a unique increasing ACK sequence number.
        let full_ack_seq_number = self.next_ack;
        self.next_ack.increment();

        // add it to the ack history
        self.ack_history_window.push(AckHistoryEntry {
            ack_number,
            ack_seq_num: Some(full_ack_seq_number),
            departure_time: now,
        });

        // 4) Calculate the packet arrival speed according to the following
        // algorithm:
        let arrival_speed = self.arrival_speed.calculate();
        let packet_recv_rate = arrival_speed.map(|(packets, _)| packets);
        let data_recv_rate = arrival_speed.map(|(_, bytes)| bytes);

        // 5) Calculate the estimated link capacity according to the following algorithm:
        let est_link_cap = self.link_capacity_estimate.calculate();

        Some(AckControlInfo::FullSmall {
            ack_number,
            rtt: self.rtt.mean(),
            rtt_variance: self.rtt.variance(),
            buffer_available: 100, // TODO: add this
            full_ack_seq_number: Some(full_ack_seq_number),
            packet_recv_rate,
            est_link_cap,
            data_recv_rate,
        })
    }

    pub fn on_nak_event(&mut self, now: Instant) -> Option<CompressedLossList> {
        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.

        // increment k and change feedback time, returning sequence numbers
        let rtt = self.rtt.mean();
        let loss_list = self
            .loss_list
            .iter_mut()
            .filter(|lle| TimeSpan::from_interval(lle.feedback_time, now) > rtt * lle.k)
            .map(|pak| {
                pak.k += 1;
                pak.feedback_time = now;

                pak.seq_num
            });
        CompressedLossList::try_from(loss_list)
    }

    pub fn handle_data_packet(
        &mut self,
        now: Instant,
        seq_number: SeqNumber,
        size: usize,
    ) -> (Option<CompressedLossList>, Option<AckControlInfo>) {
        // 4) If the sequence number of the current data packet is 16n + 1,
        //     where n is an integer, record the time interval between this
        self.link_capacity_estimate
            .record_data_packet(now, seq_number);

        // 5) Record the packet arrival time in PKT History Window.
        self.arrival_speed.record_data_packet(now, size);

        // 6)
        // a. If the sequence number of the current data packet is greater
        //    than LRSN, put all the sequence numbers between (but
        //    excluding) these two values into the receiver's loss list and
        //    send them to the sender in an NAK packet.
        let nak = match seq_number.cmp(&self.lrsn) {
            Ordering::Greater => {
                // lrsn is the latest packet received, so nak the one after that
                for i in seq_num_range(self.lrsn, seq_number) {
                    self.loss_list.push(LossListEntry {
                        seq_num: i,
                        feedback_time: now,
                        // k is initialized at 2, as stated on page 12 (very end)
                        k: 2,
                    })
                }

                CompressedLossList::try_from(seq_num_range(self.lrsn, seq_number))
            }
            // b. If the sequence number is less than LRSN, remove it from the
            //    receiver's loss list.
            Ordering::Less => {
                match self.loss_list[..].binary_search_by(|ll| ll.seq_num.cmp(&seq_number)) {
                    Ok(i) => {
                        self.loss_list.remove(i);
                    }
                    Err(_) => {
                        debug!(
                            "Packet received that's not in the loss list: {:?}, loss_list={:?}",
                            seq_number,
                            self.loss_list
                                .iter()
                                .map(|ll| ll.seq_num.as_raw())
                                .collect::<Vec<_>>()
                        );
                    }
                };
                None
            }
            Ordering::Equal => None,
        };

        // record that we got this packet
        self.lrsn = max(seq_number + 1, self.lrsn);

        // check if we need to send a light ACK
        let ack_number = self.ack_number();
        let light_ack = if ack_number - self.last_ack_number() > LIGHT_ACK_PACKET_INTERVAL {
            self.ack_history_window.push(AckHistoryEntry {
                ack_number,
                ack_seq_num: None,
                departure_time: now,
            });
            Some(AckControlInfo::Lite(ack_number))
        } else {
            None
        };

        (nak, light_ack)
    }

    pub fn handle_ack2_packet(&mut self, now: Instant, ack_seq_num: FullAckSeqNumber) {
        let ack2_arrival_time = now;

        // 1) Locate the related ACK in the ACK History Window according to the
        //    ACK sequence number in this ACK2.
        let id_in_wnd = match self
            .ack_history_window
            .as_slice()
            .binary_search_by_key(&Some(ack_seq_num), |entry| entry.ack_seq_num)
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
        } else {
            warn!(
                "ACK sequence number in ACK2 packet not found in ACK history: {:?}",
                ack_seq_num
            );
        }
    }

    // The most recent ack number, or init seq number otherwise
    fn last_ack_number(&self) -> SeqNumber {
        if let Some(he) = self.ack_history_window.last() {
            he.ack_number
        } else {
            self.init_seq_num
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

    pub fn rtt(&self) -> &Rtt {
        &self.rtt
    }
}

#[cfg(test)]
mod automatic_repeat_request_algorithm {
    use super::*;
    use std::time::Duration;

    #[test]
    fn data_packet_nak() {
        let start = Instant::now();
        let data_seq_number = SeqNumber(0);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(data_seq_number);

        assert_eq!(arq.on_full_ack_event(start), None);
        assert_eq!(arq.on_nak_event(start), None);
        assert_eq!(
            arq.handle_data_packet(start, data_seq_number, 0),
            (None, None)
        );

        assert_eq!(
            arq.handle_data_packet(start, data_seq_number + 2, 0),
            (
                CompressedLossList::try_from(seq_num_range(
                    data_seq_number + 1,
                    data_seq_number + 2
                )),
                None
            )
        );
    }

    #[test]
    fn ack_event() {
        let start = Instant::now();
        let data_seq_number = SeqNumber(0);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(data_seq_number);

        assert_eq!(
            arq.handle_data_packet(start, data_seq_number, 0),
            (None, None)
        );
        assert_eq!(
            arq.handle_data_packet(start, data_seq_number + 1, 0),
            (None, None)
        );
        assert_eq!(
            arq.on_full_ack_event(start),
            Some(AckControlInfo::FullSmall {
                ack_number: data_seq_number + 2,
                rtt: Rtt::new().mean(),
                rtt_variance: Rtt::new().variance(),
                buffer_available: 100,
                packet_recv_rate: None,
                est_link_cap: None,
                data_recv_rate: None,
                full_ack_seq_number: Some(FullAckSeqNumber::INITIAL),
            })
        );

        assert_eq!(
            arq.handle_data_packet(start, data_seq_number + 2, 0),
            (None, None)
        );
    }

    #[test]
    fn nak_event() {
        let start = Instant::now();
        let data_seq_number = SeqNumber(0);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(data_seq_number);

        arq.handle_data_packet(start, data_seq_number + 2, 0);

        let now = start + arq.rtt.mean();
        assert_eq!(arq.on_nak_event(now), None);

        let now = now + arq.rtt.mean() * 2;
        assert_eq!(
            arq.on_nak_event(now),
            CompressedLossList::try_from(seq_num_range(data_seq_number, data_seq_number + 2))
        );

        let now = now + arq.rtt.mean();
        assert_eq!(arq.on_nak_event(now), None);

        let now = now + arq.rtt.mean() * 4;
        assert_eq!(
            arq.on_nak_event(now),
            CompressedLossList::try_from(seq_num_range(data_seq_number, data_seq_number + 2))
        );
    }

    #[test]
    fn arrival_speed() {
        let seconds = Duration::from_secs;
        let mut now = Instant::now();

        let mut arrival_speed = ArrivalSpeed::new();

        let bytes_per_second = 1_000_000;
        let packets_per_second = bytes_per_second / 1_000;
        let packet_interval = seconds(1) / packets_per_second;
        for _ in 1..=7 {
            assert_eq!(arrival_speed.calculate(), None);
            now += packet_interval;
            arrival_speed.record_data_packet(now, 1_000);
        }

        // these outliers should be tossed out
        assert_eq!(arrival_speed.calculate(), None);
        now += packet_interval / 8;
        arrival_speed.record_data_packet(now, 1_000);

        assert_eq!(arrival_speed.calculate(), None);
        now += packet_interval * 8;
        arrival_speed.record_data_packet(now, 1_000);

        for _ in 10..=17 {
            assert_eq!(arrival_speed.calculate(), None);
            now += packet_interval;
            arrival_speed.record_data_packet(now, 1_000);
        }

        assert_eq!(
            arrival_speed.calculate(),
            Some((packets_per_second, bytes_per_second))
        );
    }

    #[test]
    fn link_capacity_estimate() {
        let seconds = Duration::from_secs;
        let mut now = Instant::now();
        let mut data_seq_number = SeqNumber(0);
        let mut link_capacity_estimate = LinkCapacityEstimate::new();

        assert_eq!(link_capacity_estimate.calculate(), None);

        for pairs in 1..=16 {
            let packets_per_second = pairs * 100;
            for _ in 1..=16 {
                now += seconds(1) / packets_per_second;
                link_capacity_estimate.record_data_packet(now, data_seq_number);
                data_seq_number += 1;
            }
        }

        assert_eq!(link_capacity_estimate.calculate(), Some(900));

        let packets_per_second = 1700;
        let interval = seconds(1) / packets_per_second;
        // skip seq_number % 16 == 0
        for n in 0..16 {
            if n != 0 {
                now += interval;
                link_capacity_estimate.record_data_packet(now, data_seq_number);
            }
            data_seq_number += 1;
        }
        assert_eq!(link_capacity_estimate.calculate(), Some(900));

        // skip seq_number % 16 == 1
        for n in 0..16 {
            if n != 1 {
                now += interval;
                link_capacity_estimate.record_data_packet(now, data_seq_number);
            }
            data_seq_number += 1;
        }
        assert_eq!(link_capacity_estimate.calculate(), Some(900));

        // the median calculation should update as the oldest data packet pairs leave
        // the link capacity estimate window window
        for _ in 1..=2 {
            now += interval;
            link_capacity_estimate.record_data_packet(now, data_seq_number);
            data_seq_number += 1;
        }
        assert_eq!(link_capacity_estimate.calculate(), Some(1_000));
    }
}
