use std::{
    cmp::max,
    collections::{BTreeSet, VecDeque},
    ops::Range,
    time::Duration,
};

use crate::{connection::ConnectionSettings, packet::*};

#[derive(Debug)]
pub struct SendBuffer {
    latency_window: Duration,
    flow_window_size: Option<usize>,
    buffer: VecDeque<DataPacket>,
    next_send: Option<SeqNumber>,
    next_full_ack: FullAckSeqNumber,
    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    lost_list: BTreeSet<SeqNumber>,
}

impl SendBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            buffer: VecDeque::new(),
            next_send: None,
            next_full_ack: FullAckSeqNumber::INITIAL,
            lost_list: BTreeSet::new(),
            flow_window_size: None,
            latency_window: max(
                settings.send_tsbpd_latency + settings.send_tsbpd_latency / 4, // 125% of TSBPD
                Duration::from_secs(1),
            ),
        }
    }

    pub fn push_data(&mut self, packet: DataPacket) {
        if self.buffer.is_empty() {
            self.buffer.push_back(packet.clone());
        }
        self.buffer.push_back(packet);
    }

    pub fn is_flushed(&self) -> bool {
        self.lost_list.is_empty() && self.buffer.is_empty()
    }

    pub fn has_packets_to_send(&self) -> bool {
        self.peek_next_packet().is_some() || !self.lost_list.is_empty()
    }

    pub fn update_largest_acked_seq_number(
        &mut self,
        ack_number: SeqNumber,
        full_ack: Option<FullAckSeqNumber>,
    ) -> Result<AckAction, AckError> {
        use AckError::*;
        let first = self.front_packet().ok_or(SendBufferEmpty)?;
        let next = self.next_send.ok_or(SendBufferEmpty)?;
        if ack_number < first || ack_number > next {
            return Err(InvalidAck {
                ack_number,
                first,
                next,
            });
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
            let _ = self.buffer.pop_front();
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

    fn pop_next_packet(&mut self) -> Option<DataPacket> {
        let packet = self.peek_next_packet()?.clone();
        self.next_send = Some(packet.seq_number + 1);
        Some(packet)
    }

    fn pop_next_16n_packet(&mut self) -> Option<DataPacket> {
        match self.peek_next_packet().map(|p| p.seq_number % 16) {
            Some(0) => self.pop_next_packet(),
            _ => None,
        }
    }

    fn pop_next_lost_packet(&mut self) -> Option<DataPacket> {
        let next_lost = self.pop_lost_list()?;
        let mut packet = self.get_packet(next_lost)?.clone();
        packet.retransmitted = true;
        Some(packet)
    }

    fn drop_too_late_packets(&mut self, ts_now: TimeStamp) -> Option<Range<SeqNumber>> {
        let latency_window = self.latency_window;
        let front = self
            .send_buffer()
            .next()
            .filter(|p| ts_now > p.timestamp + latency_window)?;
        let first = front.seq_number;
        let mut last = first;
        let mut message = front.message_number;
        for next in self.send_buffer() {
            if ts_now > next.timestamp + latency_window {
                message = next.message_number;
                last = next.seq_number;
            } else if next.message_number == message {
                last = next.seq_number;
            } else {
                break;
            }
        }

        let count = last - first + 1;
        let _ = self.buffer.drain(0..count as usize).count();

        self.next_send = self
            .next_send
            .filter(|next| *next > last)
            .or(Some(last + 1));

        Some(first..last + 1)
    }

    fn flush_on_close(&mut self, should_drain: bool) -> Option<DataPacket> {
        if should_drain && self.buffer.len() == 1 {
            self.next_send = None;
            self.buffer.pop_front()
        } else {
            None
        }
    }

    fn flow_window_exceeded(&self) -> bool {
        // Up to SRT 1.0.6, this value was set at 1000 pkts, which may be insufficient
        // for satellite links with ~1000 msec RTT and high bit rate.
        self.number_of_unacked_packets() > self.flow_window_size.unwrap_or(10_000)
    }

    fn number_of_unacked_packets(&self) -> usize {
        self.buffer.len().saturating_sub(1)
    }

    fn peek_next_packet(&self) -> Option<&DataPacket> {
        let front = self.front_packet()?;
        let index = self.next_send.unwrap_or(front) - front;
        self.get_at(index)
    }

    fn pop_lost_list(&mut self) -> Option<SeqNumber> {
        let next = self.lost_list.iter().copied().next()?;
        let _ = self.lost_list.remove(&next);
        Some(next)
    }

    fn peek_next_lost(&self, seq_num: SeqNumber) -> Option<SeqNumber> {
        self.lost_list
            .iter()
            .filter(|first| *(*first) < seq_num)
            .copied()
            .next()
    }

    // use these internal accessor methods to ensure we always
    // account for the one remaining packet we need to keep around
    // in order to send a final packet on flush and close
    fn get_packet(&self, seq_number: SeqNumber) -> Option<&DataPacket> {
        let front = self.front_packet()?;
        let index = seq_number - front;
        self.get_at(index)
    }

    fn front_packet(&self) -> Option<SeqNumber> {
        self.send_buffer().next().map(|p| p.seq_number)
    }

    fn send_buffer(&self) -> impl Iterator<Item = &DataPacket> {
        self.buffer.iter().skip(1)
    }

    fn get_at(&self, index: u32) -> Option<&DataPacket> {
        self.buffer.get((index + 1) as usize)
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

#[derive(Clone, Copy, Debug, PartialEq)]
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
            (_, Some(next_send)) if next >= next_send => (Ignored, next),
            (_, None) => (Dropped, next),
            (Some(front), _) if next < front => (Dropped, next),
            (None, _) => (Dropped, next),
            (Some(_), Some(_)) => {
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

#[derive(Clone, Debug, PartialEq)]
pub enum SenderAction {
    Send(DataPacket),
    Retransmit(DataPacket),
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

    fn retransmit(&mut self, p: DataPacket) -> Option<SenderAction> {
        self.packets_to_send = self.packets_to_send.saturating_sub(1);
        Some(SenderAction::Retransmit(p))
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
            if let Some(p) = self.buffer.pop_next_16n_packet() {
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
        else if let Some(p) = self.buffer.pop_next_lost_packet() {
            self.retransmit(p)
        }
        //   4)
        //        a. If the number of unacknowledged packets exceeds the
        //           flow/congestion window size, wait until an ACK comes. Go to
        //           1).
        // TODO: account for looping here <--- WAT?
        else if self.buffer.flow_window_exceeded() {
            self.wait_for_ack()
        } else if let Some(p) = self.buffer.pop_next_packet() {
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

    use crate::settings::*;

    use std::time::{Duration, Instant};

    use bytes::Bytes;

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
            max_packet_size: 1316,
            max_flow_size: 8192,
            send_tsbpd_latency: TSBPD,
            recv_tsbpd_latency: TSBPD,
            cipher: None,
            stream_id: None,
            bandwidth: LiveBandwidthMode::default(),
            recv_buffer_size: 8196,
            statistics_interval: Duration::from_secs(10),
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

    fn retransmit_data_packet(n: u32) -> SenderAction {
        SenderAction::Retransmit(test_data_packet(n, true))
    }

    #[test]
    fn send_packets() {
        use SenderAction::*;
        let start = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());
        for n in 0..=16u32 {
            buffer.push_data(test_data_packet(n, false));
        }

        for n in 0..=16 {
            let actions = buffer.next_snd_actions(start, 1, false).collect::<Vec<_>>();
            match n {
                0..=14 => assert_eq!(actions, vec![send_data_packet(n)], "n={}", n),
                // even if only 1 packet is requested, it should send the 16th packet immediately anyway
                15 => assert_eq!(actions, vec![send_data_packet(n), send_data_packet(n + 1)]),
                _ => assert_eq!(actions, vec![WaitForInput]),
            };
        }

        assert!(!buffer.has_packets_to_send());
        assert!(!buffer.is_flushed());
    }

    #[test]
    fn retransmit_packets() {
        use SenderAction::*;
        let start = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=13 {
            buffer.push_data(test_data_packet(n, false));
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
            vec![retransmit_data_packet(7), retransmit_data_packet(11),]
        );
        assert!(buffer.has_packets_to_send());

        // when there are no packets left to retransmit, wait for more data
        let actions = buffer.next_snd_actions(start, 3, false).collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                retransmit_data_packet(12),
                retransmit_data_packet(13),
                WaitForInput,
            ]
        );
        assert!(!buffer.has_packets_to_send());
    }

    #[test]
    fn ack() {
        use AckError::*;
        let now = TimeStamp::MIN;
        let mut buffer = SendBuffer::new(&new_settings());

        for n in 0..=5 {
            buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 5, false).count();
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(2), None),
            Ok(AckAction {
                received: 2,
                recovered: 0,
                send_ack2: None,
            })
        );
        let full_ack = FullAckSeqNumber::new(1);
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(4), full_ack),
            Ok(AckAction {
                received: 2,
                recovered: 0,
                send_ack2: full_ack,
            })
        );

        // ACK with from a Full ACK from the past should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(5), full_ack),
            Err(InvalidFullAck {
                received_full_ack: full_ack.unwrap(),
                next_full_ack: full_ack.unwrap() + 1
            })
        );

        // ACK for packets from the past should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(1), None),
            Err(InvalidAck {
                ack_number: SeqNumber(1),
                first: SeqNumber(4),
                next: SeqNumber(5)
            })
        );

        // ACK for unsent packets should be ignored
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(6), None),
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
            buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 3, false).count();
        assert!(!buffer.has_packets_to_send());

        //
        let _ = buffer.update_largest_acked_seq_number(SeqNumber(1), None);

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
            buffer.push_data(test_data_packet(n, false));
        }

        let _ = buffer.next_snd_actions(now, 3, false).count();
        let _ = buffer
            .add_to_loss_list([SeqNumber(1)].iter().collect())
            .count();

        // three packets received, one of them was lost but recovered
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(3), None),
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
            buffer.push_data(test_data_packet(n, false));
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
}
