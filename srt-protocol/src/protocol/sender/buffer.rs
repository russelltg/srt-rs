use crate::packet::CompressedLossList;
use crate::protocol::encryption::Cipher;
use crate::protocol::sender::encapsulate::Encapsulate;
use crate::{ConnectionSettings, DataPacket, SeqNumber};
use bytes::Bytes;
use std::cmp::max;
use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SendBuffer {
    encapsulate: Encapsulate,
    encrypt: Cipher,
    latency_window: Duration,
    buffer: VecDeque<DataPacket>,
    next_send: Option<SeqNumber>,
    // 1) Sender's Loss List: The sender's loss list is used to store the
    //    sequence numbers of the lost packets fed back by the receiver
    //    through NAK packets or inserted in a timeout event. The numbers
    //    are stored in increasing order.
    lost_list: BTreeSet<SeqNumber>,
}

impl SendBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            encapsulate: Encapsulate::new(settings),
            encrypt: Cipher::new(settings.crypto_manager.clone()),
            buffer: VecDeque::new(),
            next_send: None,
            lost_list: BTreeSet::new(),
            latency_window: max(
                settings.send_tsbpd_latency + settings.send_tsbpd_latency / 4, // 125% of TSBPD
                Duration::from_secs(1),
            ),
        }
    }

    pub fn push_data(&mut self, data: (Instant, Bytes)) -> u64 {
        let encapsulate = &mut self.encapsulate;
        let buffer = &mut self.buffer;
        let encrypt = &mut self.encrypt;
        encapsulate.encapsulate(data, |packet| {
            let (packet, _) = encrypt.encrypt(packet);
            buffer.push_back(packet);
        })
    }

    pub fn is_flushed(&self) -> bool {
        self.lost_list.is_empty() && self.buffer.is_empty()
    }

    pub fn pop_next_lost_packet(&mut self) -> Option<DataPacket> {
        let next_lost = self.pop_lost_list()?;
        let front = self.front_packet()?;
        let offset = next_lost - front;
        let mut packet = self.buffer.get(offset as usize)?.clone();
        packet.retransmitted = true;
        Some(packet)
    }

    pub fn has_packets_to_send(&self) -> bool {
        self.peek_next_packet().is_some() || !self.lost_list.is_empty()
    }

    pub fn number_of_unacked_packets(&mut self) -> u32 {
        self.buffer.len() as u32
    }

    pub fn pop_next_packet(&mut self) -> Option<DataPacket> {
        let packet = self.peek_next_packet()?.clone();
        self.next_send = Some(packet.seq_number + 1);
        Some(packet)
    }

    pub fn pop_next_16n_packet(&mut self) -> Option<DataPacket> {
        match self.peek_next_packet().map(|p| p.seq_number % 16) {
            Some(0) => self.pop_next_packet(),
            _ => None,
        }
    }

    pub fn flush_on_close(&mut self, should_drain: bool) -> Option<DataPacket> {
        if should_drain && self.buffer.len() == 1 {
            self.next_send = None;
            self.buffer.pop_front()
        } else {
            None
        }
    }

    pub fn update_largest_acked_seq_number(&mut self, ack_number: SeqNumber) -> Option<(u32, u32)> {
        let first = self.front_packet()?;
        let next = self.next_send?;
        if ack_number < first || ack_number > next {
            return None;
        }

        let mut recovered_count = 0;
        let mut received_count = 0;
        while self.peek_next_lost(ack_number).is_some() {
            let _ = self.pop_lost_list();
            recovered_count += 1;
        }
        while self
            .front_packet()
            .filter(|f| *f < ack_number - 1)
            .is_some()
        {
            let _ = self.buffer.pop_front();
            received_count += 1;
        }

        Some((received_count, recovered_count))
    }

    pub fn add_to_loss_list(
        &mut self,
        nak: CompressedLossList,
    ) -> impl Iterator<Item = (Loss, SeqNumber, SeqNumber)> + '_ {
        LossIterator {
            loss_list: nak.into_iter_decompressed(),
            first: None,
            buffer: self,
        }
    }

    pub fn drop_too_late_packets(&mut self, now: Instant) -> Option<(SeqNumber, SeqNumber)> {
        let latency_window = self.latency_window;
        let ts_now = self.encapsulate.timestamp_from(now);

        let front = self
            .buffer
            .front()
            .filter(|p| ts_now > p.timestamp + latency_window)?;
        let first = front.seq_number;
        let mut last = first;
        let mut message = front.message_number;
        for next in self.buffer.iter().skip(1) {
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

        Some((first, last))
    }

    fn front_packet(&self) -> Option<SeqNumber> {
        self.buffer.front().map(|p| p.seq_number)
    }

    fn peek_next_packet(&self) -> Option<&DataPacket> {
        let first = self.front_packet()?;
        let next_send = self.next_send.unwrap_or(first);
        let index = next_send - first;
        self.buffer.get(index as usize)
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
}

#[derive(Clone, Debug, PartialEq)]
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
    type Item = (Loss, SeqNumber, SeqNumber);

    fn next(&mut self) -> Option<Self::Item> {
        let (first_type, first) = self.first.clone().or_else(|| self.next_loss())?;
        let mut last = first;
        loop {
            match self.next_loss() {
                Some((next_type, next)) if next_type == first_type && next == last + 1 => {
                    last = next;
                    continue;
                }
                Some((next_type, next)) => {
                    self.first = Some((next_type, next));
                    return Some((first_type, first, last));
                }
                None => {
                    self.first = None;
                    return Some((first_type, first, last));
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::packet::{DataEncryption, PacketLocation};
    use crate::protocol::TimeStamp;
    use crate::*;
    use bytes::Bytes;
    use std::iter::FromIterator;
    use std::time::{Duration, Instant};

    const MILLIS: Duration = Duration::from_millis(1);
    const TSBPD: Duration = Duration::from_secs(2);

    fn new_settings(start: Instant) -> ConnectionSettings {
        ConnectionSettings {
            remote: ([127, 0, 0, 1], 2223).into(),
            remote_sockid: SocketId(2),
            local_sockid: SocketId(2),
            socket_start_time: start,
            rtt: Duration::default(),
            init_seq_num: SeqNumber::new_truncate(0),
            max_packet_size: 1316,
            max_flow_size: 8192,
            send_tsbpd_latency: TSBPD,
            recv_tsbpd_latency: TSBPD,
            crypto_manager: None,
            stream_id: None,
            bandwidth: LiveBandwidthMode::default(),
        }
    }

    #[test]
    fn not_ready_empty() {
        let start = Instant::now();
        let settings = new_settings(start);
        let mut buffer = SendBuffer::new(&settings);

        let data = Bytes::new();
        buffer.push_data((start, data));

        assert!(!buffer.is_flushed());
        assert_eq!(
            buffer.pop_next_packet(),
            Some(DataPacket {
                seq_number: SeqNumber(0),
                message_loc: PacketLocation::ONLY,
                in_order_delivery: false,
                encryption: DataEncryption::None,
                retransmitted: false,
                message_number: MsgNumber(0),
                timestamp: TimeStamp::MIN,
                dest_sockid: SocketId(2),
                payload: Bytes::new()
            })
        );

        assert!(!buffer.is_flushed());
    }

    #[test]
    fn pop_next_packet() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));
        for n in 0..=16u32 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::new()));
            assert!(buffer.has_packets_to_send());
            assert!(!buffer.is_flushed());
        }
        for n in 0..=16 {
            let next_packet = buffer.pop_next_packet().map(|p| p.seq_number.as_raw());
            let next_packet_16n = buffer.pop_next_16n_packet().map(|p| p.seq_number.as_raw());

            if n < 15 {
                assert_eq!(next_packet, Some(n));
                assert_eq!(next_packet_16n, None);
            } else if n < 16 {
                assert_eq!(next_packet, Some(n));
                assert_eq!(next_packet_16n, Some(n + 1));
            } else {
                assert_eq!(next_packet, None);
                assert_eq!(next_packet_16n, None);
            }
        }
        assert!(!buffer.has_packets_to_send());
        assert!(!buffer.is_flushed());
    }

    #[test]
    fn pop_next_lost_packet() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));

        for n in 0..=13 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::new()));
        }

        for _ in 0..=11 {
            assert_ne!(buffer.pop_next_packet(), None);
        }

        assert_eq!(buffer.pop_next_lost_packet(), None);

        assert!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(11), SeqNumber(13)].into_iter(),
                ))
                .count()
                > 0
        );
        assert!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(7), SeqNumber(12)].into_iter(),
                ))
                .count()
                > 0
        );

        // the spec suggests the loss list should be ordered smallest to largest
        let next = buffer
            .pop_next_lost_packet()
            .map(|p| (p.seq_number.as_raw(), p.retransmitted));
        assert_eq!(next, Some((7, true)));
        let next = buffer
            .pop_next_lost_packet()
            .map(|p| (p.seq_number.as_raw(), p.retransmitted));
        assert_eq!(next, Some((11, true)));

        assert_eq!(buffer.pop_next_lost_packet(), None);

        assert!(buffer.has_packets_to_send());
        assert!(!buffer.is_flushed());
    }

    #[test]
    fn on_ack() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));

        assert!(buffer.is_flushed());

        for n in 0..=3 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::new()));
        }

        for _ in 0..=2 {
            assert_ne!(buffer.pop_next_packet(), None);
        }

        assert_eq!(buffer.number_of_unacked_packets(), 4);
        // mark two packets received, one packet is kept around for retransmit on flush
        // keeping this original behavior intact otherwise integration tests fail
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(3)),
            Some((2, 0))
        );
        assert_eq!(buffer.number_of_unacked_packets(), 2);
        assert!(!buffer.is_flushed());
        assert!(buffer.has_packets_to_send());

        // NAK for packets from the past should be ignored
        assert!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(1)].into_iter(),
                ))
                .count()
                > 0
        );
        assert_eq!(buffer.pop_next_lost_packet(), None);
        assert_eq!(buffer.number_of_unacked_packets(), 2);
        assert!(!buffer.is_flushed());
        assert!(buffer.has_packets_to_send());

        // ACK for unsent packets should be ignored
        assert_eq!(buffer.update_largest_acked_seq_number(SeqNumber(4)), None);
        assert_eq!(buffer.number_of_unacked_packets(), 2);
        assert!(!buffer.is_flushed());
        assert!(buffer.has_packets_to_send());

        assert_ne!(buffer.pop_next_packet(), None);
        assert_eq!(buffer.pop_next_packet(), None);
        assert_eq!(buffer.number_of_unacked_packets(), 2);
        assert!(!buffer.is_flushed());
        assert!(!buffer.has_packets_to_send());

        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(4)),
            Some((1, 0))
        );
        assert_eq!(buffer.number_of_unacked_packets(), 1);
        assert!(!buffer.is_flushed());
        assert!(!buffer.has_packets_to_send());
    }

    #[test]
    fn nak_then_ack() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));

        for n in 0..=2 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::new()));
            assert_ne!(buffer.pop_next_packet(), None);
        }

        assert!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(1)].into_iter(),
                ))
                .count()
                > 0
        );
        // two packets received, one recovered
        assert_eq!(
            buffer.update_largest_acked_seq_number(SeqNumber(3)),
            Some((2, 1))
        );
        assert_eq!(buffer.pop_next_lost_packet(), None);

        assert_eq!(buffer.number_of_unacked_packets(), 1);
        assert!(!buffer.has_packets_to_send());
        assert!(!buffer.is_flushed());
    }

    #[test]
    fn drop_too_late_packets_queued() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));
        for n in 0..=2 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::from_iter([0u8; 2048])));
        }

        // only drop the too late packets, leave the rest queued
        let now = start + TSBPD + TSBPD / 4 + 2 * MILLIS;
        assert_eq!(
            buffer.drop_too_late_packets(now),
            Some((SeqNumber(0), SeqNumber(3)))
        );

        assert_eq!(buffer.drop_too_late_packets(now), None);
        assert!(!buffer.is_flushed())
    }

    #[test]
    fn drop_too_late_packets_sent() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));
        for n in 0..=2 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::from_iter([0u8; 2048])));
        }

        // simulate sending packets from the first two messages
        assert_ne!(buffer.pop_next_packet(), None);
        assert_ne!(buffer.pop_next_packet(), None);
        assert_ne!(buffer.pop_next_packet(), None);

        // only drop the too late packets, leave the rest queued
        let now = start + TSBPD + TSBPD / 4 + 2 * MILLIS;
        assert_eq!(
            buffer.drop_too_late_packets(now),
            Some((SeqNumber(0), SeqNumber(3)))
        );

        assert_eq!(buffer.drop_too_late_packets(now), None);
        assert!(!buffer.is_flushed())
    }

    #[test]
    fn drop_too_late_packets_lost() {
        let start = Instant::now();
        let mut buffer = SendBuffer::new(&new_settings(start));
        for n in 0..=2 {
            let now = start + n * MILLIS;
            buffer.push_data((now, Bytes::from_iter([0u8; 2048])));
        }

        // simulate sending packets from the first two messages
        assert_ne!(buffer.pop_next_packet(), None);
        assert_ne!(buffer.pop_next_packet(), None);
        assert_ne!(buffer.pop_next_packet(), None);

        use Loss::*;
        assert_eq!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(1), SeqNumber(2), SeqNumber(3), SeqNumber(5)].into_iter(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (Added, SeqNumber(1), SeqNumber(2)),
                (Ignored, SeqNumber(3), SeqNumber(3)),
                (Ignored, SeqNumber(5), SeqNumber(5)),
            ]
        );

        // only drop the too late packets, leave the rest queued
        let now = start + TSBPD + TSBPD / 4 + 2 * MILLIS;
        assert_eq!(
            buffer.drop_too_late_packets(now),
            Some((SeqNumber(0), SeqNumber(3)))
        );

        assert_eq!(buffer.drop_too_late_packets(now), None);
        assert!(!buffer.is_flushed());

        assert_eq!(
            buffer
                .add_to_loss_list(CompressedLossList::from_loss_list(
                    vec![SeqNumber(1), SeqNumber(2), SeqNumber(3), SeqNumber(5)].into_iter(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (Dropped, SeqNumber(1), SeqNumber(3)),
                (Ignored, SeqNumber(5), SeqNumber(5)),
            ]
        );
    }
}
