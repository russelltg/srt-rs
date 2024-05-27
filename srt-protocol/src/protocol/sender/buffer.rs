use std::{
    cmp::{max, Reverse},
    collections::{BTreeSet, VecDeque},
    convert::TryFrom,
    ops::Range,
    time::Duration,
};

use keyed_priority_queue::KeyedPriorityQueue;

use crate::{
    connection::ConnectionSettings,
    options::{ByteCount, PacketCount},
    packet::*,
    protocol::time::{Rtt, Timers},
};

#[derive(Debug)]
pub struct SendBuffer {
    latency_window: Duration,
    flow_window_size: usize,
    buffer: VecDeque<SendBufferEntry>,
    max_buffer_size: usize,
    buffer_len_bytes: usize, // Invariant: buffer_len_bytes = sum of wire sizes of buffer
    next_send: SeqNumber,
    next_full_ack: FullAckSeqNumber,
    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    lost_list: BTreeSet<SeqNumber>,
    rtt: Rtt,
    rto_queue: KeyedPriorityQueue<SeqNumber, Reverse<(TimeStamp, SeqNumber)>>,
}

#[derive(Debug)]
struct SendBufferEntry {
    packet: DataPacket,
    // this is transmit count, including the one that may be lost
    // ie, the first time a packet is sent, this is one
    transmit_count: i32,
}

type DroppedPackets = (PacketCount, ByteCount);
type PushDataResult = Result<(), DroppedPackets>;

impl SendBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            buffer: VecDeque::new(),
            buffer_len_bytes: 0,
            next_send: settings.init_seq_num,
            next_full_ack: FullAckSeqNumber::INITIAL,
            lost_list: BTreeSet::new(),
            flow_window_size: settings.max_flow_size.0 as usize,
            max_buffer_size: settings.send_buffer_size.0 as usize,
            latency_window: max(
                settings.send_tsbpd_latency + settings.send_tsbpd_latency / 4, // 125% of TSBPD
                Duration::from_secs(1),
            ),
            rtt: Rtt::default(),
            rto_queue: Default::default(),
        }
    }

    pub fn push_data(&mut self, packet: DataPacket) -> PushDataResult {
        let result = if self.buffer.len() < self.max_buffer_size {
            Ok(())
        } else if let Some(entry) = self.buffer.pop_front() {
            self.buffer_len_bytes -= entry.packet.wire_size();

            // remove packet from lost list if we are dropping it
            if self.lost_list.first() == Some(&entry.packet.seq_number) {
                self.pop_lost_list();
            }

            Err((PacketCount(1), ByteCount(entry.packet.wire_size() as u64)))
        } else {
            Ok(())
        };

        self.buffer_len_bytes += packet.wire_size();
        self.buffer.push_back(SendBufferEntry {
            packet,
            transmit_count: 0,
        });

        result
    }

    pub fn is_flushed(&self) -> bool {
        self.lost_list.is_empty() && self.buffer.is_empty()
    }

    pub fn has_packets_to_send(&self) -> bool {
        self.get(self.next_send).is_some() || !self.lost_list.is_empty()
    }

    pub fn duration(&self) -> Duration {
        match (self.buffer.front(), self.buffer.back()) {
            (Some(f), Some(l)) => Duration::from_micros(
                u64::try_from((l.packet.timestamp - f.packet.timestamp).as_micros()).unwrap_or(0),
            ),
            _ => Duration::from_secs(0),
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn len_bytes(&self) -> usize {
        self.buffer_len_bytes
    }

    pub fn update_largest_acked_seq_number(
        &mut self,
        ack_number: SeqNumber,
        full_ack: Option<FullAckSeqNumber>,
        rtt: Option<Rtt>,
    ) -> Result<AckAction, AckError> {
        use AckError::*;
        let first = self.front_packet().ok_or(SendBufferEmpty)?;
        let next = self.next_send;
        if ack_number < first || ack_number > next {
            return Err(InvalidAck {
                ack_number,
                first,
                next,
            });
        }

        if let Some(rtt) = rtt {
            self.rtt = rtt;
        }

        if let Some(received_full_ack) = full_ack {
            if received_full_ack < self.next_full_ack {
                return Err(InvalidFullAck {
                    received_full_ack,
                    next_full_ack: self.next_full_ack,
                });
            }
            self.next_full_ack = received_full_ack + 1;
        }

        let mut recovered = 0;
        let mut received = 0;
        while self.peek_next_lost(ack_number).is_some() {
            let _ = self.pop_lost_list();
            recovered += 1;
        }

        while self.front_packet().filter(|f| *f < ack_number).is_some() {
            let p = self.pop_front().unwrap();
            self.buffer_len_bytes = self.buffer_len_bytes.saturating_sub(p.packet.wire_size());

            received += 1;
        }

        Ok(AckAction {
            received,
            recovered,
            send_ack2: full_ack,
        })
    }

    pub fn add_to_loss_list(
        &mut self,
        nak: CompressedLossList,
    ) -> impl Iterator<Item = (Loss, Range<SeqNumber>)> + '_ {
        LossIterator {
            loss_list: nak.into_iter_decompressed(),
            first: None,
            buffer: self,
        }
    }

    pub fn next_snd_actions(
        &mut self,
        ts_now: TimeStamp,
        packets_to_send: u32,
        should_drain: bool,
    ) -> impl Iterator<Item = SenderAction> + '_ {
        SenderAlgorithmIterator::new(self, ts_now, packets_to_send, should_drain)
    }

    fn send_next_packet(&mut self, ts_now: TimeStamp) -> Option<DataPacket> {
        let packet_to_send = self.send_packet(ts_now, self.next_send)?;
        self.next_send += 1; // increment after send_packet, which can return None
        Some(packet_to_send)
    }

    fn send_next_16n_packet(&mut self, ts_now: TimeStamp) -> Option<DataPacket> {
        if self.next_send % 16 == 0 {
            self.send_next_packet(ts_now)
        } else {
            None
        }
    }

    fn send_next_lost_packet(&mut self, ts_now: TimeStamp) -> Option<DataPacket> {
        let seq = self.pop_lost_list()?;
        match self
            .send_packet(ts_now, seq)
        {
            Some(packet) => Some(packet),
            None => panic!("Packet in loss list was not in buffer! seq={} front_packet={:?} buffer.len={} back_packet={:?}", seq, self.front_packet(), self.buffer.len(), self.buffer.back().map(|b| b.packet.seq_number)),
        }
    }

    fn send_next_rto_packet(&mut self, ts_now: TimeStamp) -> Option<DataPacket> {
        let next_rto = *self
            .rto_queue
            .peek()
            .filter(|(_, rto)| rto.0 .0 < ts_now)?
            .0;
        self.send_packet(ts_now, next_rto)
    }

    // All packets that are sent go through this function
    // It records transmit count and sets the per entry RTO timer
    fn send_packet(&mut self, ts_now: TimeStamp, seq_number: SeqNumber) -> Option<DataPacket> {
        let index = seq_number - self.front_packet()?;
        let entry = self.buffer.get_mut(index as usize)?;

        // RTT + 4 * RTTVar + 2 * SYN
        let rto_constant = self.rtt.mean() + 4 * self.rtt.variance() + 2 * Timers::SYN;
        let rto = if entry.transmit_count == 0 {
            rto_constant
        } else {
            // RTO = RexmitCount * (RTT + 4 * RTTVar + 2 * SYN) + SYN
            entry.transmit_count * rto_constant + Timers::SYN
        };
        let _ = self
            .rto_queue
            .push(seq_number, Reverse((ts_now + rto, seq_number)));

        // clone packet first, then update retransmitted flag
        // this way, only the first will have it as false
        let packet = entry.packet.clone();
        entry.packet.retransmitted = true;
        entry.transmit_count += 1;

        Some(packet)
    }

    fn drop_too_late_packets(&mut self, ts_now: TimeStamp) -> Option<Range<SeqNumber>> {
        let latency_window = self.latency_window;
        let front = &self
            .buffer
            .front()
            .filter(|p| ts_now > p.packet.timestamp + latency_window)?
            .packet;

        let first = front.seq_number;
        let mut last = first;
        let mut message = front.message_number;
        for next in self.buffer.iter() {
            if ts_now > next.packet.timestamp + latency_window {
                message = next.packet.message_number;
                last = next.packet.seq_number;
            } else if next.packet.message_number == message {
                last = next.packet.seq_number;
            } else {
                break;
            }
        }

        let drop_range = first..last + 1;

        let count = last - first + 1;
        let _ = self.buffer.drain(0..count as usize).count();

        // remove any lost packets from loss list
        while let Some(&seq) = self.lost_list.iter().next() {
            if drop_range.contains(&seq) {
                self.lost_list.remove(&seq);
            } else {
                break;
            }
        }

        self.next_send = max(self.next_send, last + 1);
        Some(drop_range)
    }

    fn flush_on_close(&mut self, should_drain: bool) -> Option<DataPacket> {
        if should_drain && self.buffer.len() == 1 {
            // self.next_send = None; TODO: i'm not sure what functionality this was supposed to expose

            let p = self.pop_front().map(|p| p.packet);
            // This needs to be saturating because of the hack in Self::push_data, can be regular subtract otherwise
            self.buffer_len_bytes = self
                .buffer_len_bytes
                .saturating_sub(p.as_ref().unwrap().wire_size());
            p
        } else {
            None
        }
    }

    fn flow_window_exceeded(&self) -> bool {
        self.number_of_unacked_packets() > self.flow_window_size
    }

    fn number_of_unacked_packets(&self) -> usize {
        self.buffer
            .front()
            .map_or(0, |e| self.next_send - e.packet.seq_number) as usize
    }

    fn pop_lost_list(&mut self) -> Option<SeqNumber> {
        let next = self.lost_list.iter().copied().next()?;
        let _ = self.lost_list.remove(&next);
        Some(next)
    }

    // find the first item that has a sequence number less than seq_num in the loss list
    fn peek_next_lost(&self, seq_num: SeqNumber) -> Option<SeqNumber> {
        self.lost_list.range(..seq_num).copied().next()
    }

    fn pop_front(&mut self) -> Option<SendBufferEntry> {
        let entry = self.buffer.pop_front()?;
        let _ = self.rto_queue.remove(&entry.packet.seq_number);
        Some(entry)
    }

    fn get(&self, seq: SeqNumber) -> Option<&SendBufferEntry> {
        self.buffer.get((seq - self.front_packet()?) as usize)
    }

    fn front_packet(&self) -> Option<SeqNumber> {
        self.buffer.front().map(|p| p.packet.seq_number)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AckError {
    InvalidFullAck {
        received_full_ack: FullAckSeqNumber,
        next_full_ack: FullAckSeqNumber,
    },
    InvalidAck {
        ack_number: SeqNumber,
        first: SeqNumber,
        next: SeqNumber,
    },
    SendBufferEmpty,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AckAction {
    pub received: u64,
    pub recovered: u64,
    pub send_ack2: Option<FullAckSeqNumber>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loss {
    Added,
    Dropped,
    Ignored,
}

pub struct LossIterator<'a, I: Iterator<Item = SeqNumber>> {
    buffer: &'a mut SendBuffer,
    loss_list: I,
    first: Option<(Loss, SeqNumber)>,
}

impl<'a, I> LossIterator<'a, I>
where
    I: Iterator<Item = SeqNumber>,
{
    fn next_loss(&mut self) -> Option<(Loss, SeqNumber)> {
        use Loss::*;
        let front = self.buffer.front_packet();
        let next_send = self.buffer.next_send;
        self.loss_list.next().map(|next| match (front, next_send) {
            (_, next_send) if next >= next_send => (Ignored, next),
            (Some(front), _) if next < front => (Dropped, next),
            (None, _) => (Dropped, next),
            (Some(_), _) => {
                self.buffer.lost_list.insert(next);
                (Added, next)
            }
        })
    }
}

impl<'a, I> Iterator for LossIterator<'a, I>
where
    I: Iterator<Item = SeqNumber>,
{
    type Item = (Loss, Range<SeqNumber>);

    fn next(&mut self) -> Option<Self::Item> {
        let (first_type, start) = self.first.or_else(|| self.next_loss())?;
        // exclusive end
        let mut end = start + 1;
        loop {
            match self.next_loss() {
                Some((next_type, next)) if next_type == first_type && next == end => {
                    end = next + 1;
                    continue;
                }
                Some((next_type, next)) => {
                    self.first = Some((next_type, next));
                    return Some((first_type, start..end));
                }
                None => {
                    self.first = None;
                    return Some((first_type, start..end));
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SenderAction {
    Send(DataPacket),
    // Retransmission from RTO
    RetransmitRto(DataPacket),
    // Retransmission from NAK
    RetransmitNak(DataPacket),
    Drop(Range<SeqNumber>),
    WaitForInput,
    // sender flow window exceeded"
    WaitForAck {
        window_size: u32,
        unacked_packets: u32,
    },
}

pub struct SenderAlgorithmIterator<'a> {
    buffer: &'a mut SendBuffer,
    ts_now: TimeStamp,
    should_drain: bool,
    packets_to_send: u32,
    attempt_16n_packet: bool,
}

impl<'a> SenderAlgorithmIterator<'a> {
    pub fn new(
        buffer: &'a mut SendBuffer,
        ts_now: TimeStamp,
        packets_to_send: u32,
        should_drain: bool,
    ) -> Self {
        Self {
            buffer,
            ts_now,
            should_drain,
            packets_to_send,
            attempt_16n_packet: false,
        }
    }

    fn send(&mut self, p: DataPacket) -> Option<SenderAction> {
        self.packets_to_send = self.packets_to_send.saturating_sub(1);
        Some(SenderAction::Send(p))
    }

    fn retransmit_nak(&mut self, p: DataPacket) -> Option<SenderAction> {
        self.packets_to_send = self.packets_to_send.saturating_sub(1);
        Some(SenderAction::RetransmitNak(p))
    }

    fn retransmit_rto(&mut self, p: DataPacket) -> Option<SenderAction> {
        self.packets_to_send = self.packets_to_send.saturating_sub(1);
        Some(SenderAction::RetransmitRto(p))
    }

    fn wait_for_input(&mut self) -> Option<SenderAction> {
        self.packets_to_send = 0;
        Some(SenderAction::WaitForInput)
    }

    fn wait_for_ack(&mut self) -> Option<SenderAction> {
        self.packets_to_send = 0;
        Some(SenderAction::WaitForAck {
            window_size: 10_000,
            unacked_packets: self.buffer.number_of_unacked_packets() as u32,
        })
    }

    fn drop(&self, range: Range<SeqNumber>) -> Option<SenderAction> {
        Some(SenderAction::Drop(range))
    }
}

impl<'a> Iterator for SenderAlgorithmIterator<'a> {
    type Item = SenderAction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attempt_16n_packet {
            self.attempt_16n_packet = false;
            if let Some(p) = self.buffer.send_next_16n_packet(self.ts_now) {
                return self.send(p);
            }
        }

        // respect congestion control
        if self.packets_to_send == 0 {
            return None;
        }

        // NOTE: 2) before 1) so we drop loss list packets if they are too late
        //
        //   2) In messaging mode, if the packets have been in the loss list for a
        //      time more than the application specified TTL, send a message drop
        //      request and remove all related packets from the loss list. Go to
        //      1).
        if let Some(range) = self.buffer.drop_too_late_packets(self.ts_now) {
            self.drop(range)
        }
        //   1) If the sender's loss list is not empty, retransmit the first
        //      packet in the list and remove it from the list. Go to 5).
        //
        // NOTE: the reference implementation doesn't jump to 5), so we don't either
        else if let Some(p) = self.buffer.send_next_lost_packet(self.ts_now) {
            self.retransmit_nak(p)
        } else if let Some(p) = self.buffer.send_next_rto_packet(self.ts_now) {
            self.retransmit_rto(p)
        }
        //   4)
        //        a. If the number of unacknowledged packets exceeds the
        //           flow/congestion window size, wait until an ACK comes. Go to
        //           1).
        // TODO: account for looping here <--- WAT?
        else if self.buffer.flow_window_exceeded() {
            self.wait_for_ack()
        } else if let Some(p) = self.buffer.send_next_packet(self.ts_now) {
            //        b. Pack a new data packet and send it out.
            //   5) If the sequence number of the current packet is 16n, where n is an
            //      integer, go to 2).
            //
            //      NOTE: to get the closest timing, we ignore congestion control
            //      and send the 16th packet immediately, instead of proceeding to step 2
            self.attempt_16n_packet = true;

            self.send(p)
        } else if let Some(p) = self.buffer.flush_on_close(self.should_drain) {
            self.send(p)
        } else {
            // NOTE: we wait the same amount regardless if we are waiting for packets or data
            //
            //   3) Wait until there is application data to be sent.
            //
            //   6) Wait (SND - t) time, where SND is the inter-packet interval
            //      updated by congestion control and t is the total time used by step
            //      1 to step 5. Go to 1).

            // NOTE: because this sender algorithm iterator code only runs when SND is triggered,
            // exiting the SND event handler will satisfy 6), though we'll update SND as well to
            // ensure congestion control is respected.
            self.wait_for_input()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::time::{Duration, Instant};

    use assert_matches::assert_matches;
    use bytes::Bytes;

    use crate::options::{PacketCount, PacketSize};

    const MILLIS: Duration = Duration::from_millis(1);
    const TSBPD: Duration = Duration::from_secs(2);

    fn new_settings() -> ConnectionSettings {
        ConnectionSettings {
            remote: ([127, 0, 0, 1], 2223).into(),
            remote_sockid: SocketId(2),
            local_sockid: SocketId(2),
            socket_start_time: Instant::now(),
            rtt: Duration::default(),
            init_seq_num: SeqNumber::new_truncate(0),
            max_packet_size: PacketSize(1316),
            max_flow_size: PacketCount(8192),
            send_tsbpd_latency: TSBPD,
            recv_tsbpd_latency: TSBPD,
            cipher: None,
            stream_id: None,
            bandwidth: Default::default(),
            recv_buffer_size: PacketCount(8196),
            send_buffer_size: PacketCount(8196),
            statistics_interval: Duration::from_secs(10),
            peer_idle_timeout: Duration::from_secs(5),
            too_late_packet_drop: true,
        }
    }

    fn test_data_packet(n: u32, retransmitted: bool) -> DataPacket {
        DataPacket {
            seq_number: SeqNumber(n),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            message_number: MsgNumber(n / 2),
            timestamp: TimeStamp::MIN + n * MILLIS,
            dest_sockid: SocketId(2),
            payload: Bytes::new(),
            retransmitted,
        }
    }

    fn send_data_packet(n: u32) -> SenderAction {
        SenderAction::Send(test_data_packet(n, false))
    }

    fn nak_retransmit_packet(n: u32) -> SenderAction {
        SenderAction::RetransmitNak(test_data_packet(n, true))
    }

    #[test]
    fn send_packets() {
        use SenderAction::*;
        let start = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());
        for n in 0..=16u32 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        for n in 0..=16 {
            let actions = buffer.next_snd_actions(start, 1, false).collect::<Vec<_>>();
            match n {
                0..=14 => assert_eq!(actions, vec![send_data_packet(n)], "n={n}"),
                // even if only 1 packet is requested, it should send the 16th packet immediately anyway
                15 => assert_eq!(actions, vec![send_data_packet(n), send_data_packet(n + 1)]),
                _ => assert_eq!(actions, vec![WaitForInput]),
            };
        }

        assert!(!buffer.has_packets_to_send());
        assert!(!buffer.is_flushed());
    }

    #[test]
    fn nak_retransmit() {
        use SenderAction::*;
        let start = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=13 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        let actions = buffer
            .next_snd_actions(start, 14, false)
            .filter(|a| !matches!(a, &Send(_)))
            .collect::<Vec<_>>();
        assert_eq!(actions, vec![]);
        assert!(!buffer.has_packets_to_send());

        // simulate NAKs with overlapping nad out of order sequence numbers
        let _ = buffer
            .add_to_loss_list([SeqNumber(11), SeqNumber(13)].iter().collect())
            .count();
        let _ = buffer
            .add_to_loss_list([SeqNumber(7), SeqNumber(12)].iter().collect())
            .count();
        assert!(buffer.has_packets_to_send());

        // retransmit lost packets
        // prioritize the oldest packets: retransmit in order of ascending sequence number
        let actions = buffer.next_snd_actions(start, 2, false).collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![nak_retransmit_packet(7), nak_retransmit_packet(11),]
        );
        assert!(buffer.has_packets_to_send());

        // when there are no packets left to retransmit, wait for more data
        let actions = buffer.next_snd_actions(start, 3, false).collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                nak_retransmit_packet(12),
                nak_retransmit_packet(13),
                WaitForInput,
            ]
        );
        assert!(!buffer.has_packets_to_send());
    }

    #[test]
    fn rto_retransmit() {
        use SenderAction::*;
        let start = TimeStamp::MAX;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=2 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        assert_eq!(buffer.next_snd_actions(start, 3, false).count(), 3);

        assert_eq!(
            buffer.next_snd_actions(start, 3, false).collect::<Vec<_>>(),
            vec![WaitForInput]
        );

        let now = start + TimeSpan::from_millis(1_000);

        let actions = buffer.next_snd_actions(now, 3, false).collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                RetransmitRto(test_data_packet(0, true)),
                RetransmitRto(test_data_packet(1, true)),
                RetransmitRto(test_data_packet(2, true)),
            ]
        );
    }

    #[test]
    fn ack() {
        use AckError::*;
        let now = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=5 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 5, false).count();
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(2), None, None),
            Ok(AckAction {
                received: 2,
                recovered: 0,
                send_ack2: None,
            })
        );
        let full_ack = FullAckSeqNumber::new(1);
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(4), full_ack, None),
            Ok(AckAction {
                received: 2,
                recovered: 0,
                send_ack2: full_ack,
            })
        );

        // ACK with from a Full ACK from the past should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(5), full_ack, None),
            Err(InvalidFullAck {
                received_full_ack: full_ack.unwrap(),
                next_full_ack: full_ack.unwrap() + 1
            })
        );

        // ACK for packets from the past should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(1), None, None),
            Err(InvalidAck {
                ack_number: SeqNumber(1),
                first: SeqNumber(4),
                next: SeqNumber(5)
            })
        );

        // ACK for unsent packets should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(6), None, None),
            Err(InvalidAck {
                ack_number: SeqNumber(6),
                first: SeqNumber(4),
                next: SeqNumber(5)
            })
        );
    }

    #[test]
    fn nak() {
        use Loss::*;
        let now = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=2 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 3, false).count();
        assert!(!buffer.has_packets_to_send());

        let _ = buffer.update_largest_acked_seq_number(SeqNumber(1), None, None);

        let loss = buffer
            .add_to_loss_list(
                [SeqNumber(0), SeqNumber(1), SeqNumber(2), SeqNumber(3)]
                    .iter()
                    .collect(),
            )
            .collect::<Vec<_>>();
        assert_eq!(
            loss,
            vec![
                (Dropped, SeqNumber(0)..SeqNumber(1)),
                (Added, SeqNumber(1)..SeqNumber(3)),
                (Ignored, SeqNumber(3)..SeqNumber(4)),
            ]
        );
        assert!(buffer.has_packets_to_send());

        // handle duplicate NAKs gracefully
        let loss = buffer
            .add_to_loss_list([SeqNumber(1), SeqNumber(2)].iter().collect())
            .collect::<Vec<_>>();
        assert_eq!(loss, vec![(Added, SeqNumber(1)..SeqNumber(3)),]);
    }

    #[test]
    fn nak_then_ack() {
        let now = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=2 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 3, false).count();
        let _ = buffer
            .add_to_loss_list([SeqNumber(1)].iter().collect())
            .count();

        // three packets received, one of them was lost but recovered
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(3), None, None),
            Ok(AckAction {
                received: 3,
                recovered: 1,
                send_ack2: None
            })
        );
        assert!(!buffer.has_packets_to_send());
    }

    #[test]
    fn drop_too_late_packets() {
        use Loss::*;
        use SenderAction::*;
        let start = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());
        for n in 0..=4 {
            let _ = buffer.push_data(test_data_packet(n, false));
        }

        // drop queued packets when they are too late
        // send the reset or leave them queued
        let ts_now = start + TSBPD + TSBPD / 4 + 2 * MILLIS;
        let actions = buffer
            .next_snd_actions(ts_now, 1, false)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![Drop(SeqNumber(0)..SeqNumber(2)), send_data_packet(2)]
        );
        assert!(buffer.has_packets_to_send());

        // drop sent packets too
        let ts_now = ts_now + 2 * MILLIS;
        let actions = buffer
            .next_snd_actions(ts_now, 1, false)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![Drop(SeqNumber(2)..SeqNumber(4)), send_data_packet(4)]
        );
        assert!(!buffer.has_packets_to_send());

        // drop lost packets too
        assert_eq!(
            buffer
                .add_to_loss_list([SeqNumber(4)].iter().collect())
                .collect::<Vec<_>>(),
            vec![(Added, SeqNumber(4)..SeqNumber(5))]
        );
        assert!(buffer.has_packets_to_send());
        let ts_now = ts_now + 4 * MILLIS;
        let actions = buffer
            .next_snd_actions(ts_now, 1, false)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![Drop(SeqNumber(4)..SeqNumber(5)), WaitForInput]
        );
        assert!(!buffer.has_packets_to_send());
        assert!(buffer.lost_list.is_empty());
    }

    #[test]
    fn buffer_duration_size() {
        use SenderAction::*;

        let mut buffer = SendBuffer::new(&new_settings());
        assert_eq!(buffer.duration(), Duration::from_micros(0));

        let wire_size = test_data_packet(0, false).wire_size();

        for n in 0..10 {
            let _ = buffer.push_data(test_data_packet(n, false));
            assert_eq!(buffer.duration(), Duration::from_millis(1) * n);
            assert_eq!(buffer.len(), n as usize + 1);
            assert_eq!(buffer.len_bytes(), wire_size * (n as usize + 1));
        }

        for n in 0..10 {
            let a = buffer
                .next_snd_actions(TimeStamp::MIN + n * TimeSpan::from_micros(1_000), 1, false)
                .collect::<Vec<_>>();
            assert_eq!(a.len(), 1);
            assert_matches!(a[0], Send(_));
            assert_eq!(buffer.duration(), Duration::from_millis(9)); // not removed from buffer until ack

            assert_eq!(buffer.len(), 10);
            assert_eq!(buffer.len_bytes(), wire_size * 10);
        }

        for n in 0..10 {
            buffer
                .update_largest_acked_seq_number(SeqNumber(n + 1), None, None)
                .unwrap();

            assert_eq!(
                buffer.duration(),
                Duration::from_millis(8u64.saturating_sub(n.into()))
            );
            assert_eq!(buffer.len(), 9 - n as usize);
            assert_eq!(buffer.len_bytes(), wire_size * (9 - n as usize));
        }
    }

    #[test]
    fn flow_window_exceeded() {
        let mut buffer = SendBuffer::new(&new_settings());

        let max_flow_size = new_settings().max_flow_size.0 as u32 + 1;
        for n in 0..max_flow_size {
            assert_eq!(buffer.push_data(test_data_packet(n, false)), Ok(()));
        }

        // if the buffer is full of unsent packets it
        assert!(!buffer.flow_window_exceeded());

        // if the buffer is full of too many packets sent and un-ACKed packets, it will exceed the flow window
        let actions = buffer.next_snd_actions(TimeStamp::MIN, max_flow_size, false);
        assert_eq!(actions.count(), max_flow_size as usize);
        assert!(buffer.flow_window_exceeded());

        // if the sent packets in the buffer are then dropped before they are ACKed, it will no longer exceed the flow window
        let latency = Duration::from_secs(10);
        let action = buffer.next_snd_actions(TimeStamp::MIN + latency, max_flow_size, false);
        assert!(action.count() > 1);
        assert!(!buffer.flow_window_exceeded());
    }

    #[test]
    fn max_send_buffer_size() {
        let mut buffer = SendBuffer::new(&new_settings());

        let send_buffer_size = new_settings().send_buffer_size.0 as u32;
        for n in 0..send_buffer_size {
            assert_eq!(buffer.push_data(test_data_packet(n, false)), Ok(()));
        }

        let expected_dropped_bytes = test_data_packet(0, false).wire_size() as u64;
        let overflow_packet = test_data_packet(send_buffer_size, false);
        assert_eq!(
            buffer.push_data(overflow_packet),
            Err((PacketCount(1), ByteCount(expected_dropped_bytes)))
        );
    }

    #[test]
    fn loss_then_fill_buffer() {
        let now = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=2 {
            assert_matches!(buffer.push_data(test_data_packet(n, false)), Ok(_));
        }

        let _ = buffer.next_snd_actions(now, 3, false).count();
        let _ = buffer
            .add_to_loss_list([SeqNumber(1)].iter().collect())
            .count();

        for n in 3..=8195 {
            assert_matches!(buffer.push_data(test_data_packet(n, false)), Ok(_));
        }
        assert_matches!(buffer.push_data(test_data_packet(8296, false)), Err(_));
        assert_matches!(buffer.push_data(test_data_packet(8297, false)), Err(_));

        buffer.send_next_lost_packet(now);
    }
}
