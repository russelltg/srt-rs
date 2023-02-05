use std::{
    cmp::min,
    collections::VecDeque,
    convert::TryFrom,
    ops::Range,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use take_until::TakeUntilExt;

use crate::{options::PacketCount, packet::*};

use super::{
    time::{ClockAdjustment, SynchronizedRemoteClock},
    DataPacketAction, DataPacketError,
};

#[derive(Debug)]
pub struct LostPacket {
    data_sequence_number: SeqNumber,
    feedback_time: Instant,
    k: i32,
}

impl LostPacket {
    pub fn new(data_sequence_number: SeqNumber, feedback_time: Instant) -> Self {
        Self {
            data_sequence_number,
            feedback_time,
            k: 2,
        }
    }
}

#[derive(Debug)]
pub enum BufferPacket {
    Lost(LostPacket),
    Received(DataPacket),
    Dropped(SeqNumber),
}

impl BufferPacket {
    pub fn data_sequence_number(&self) -> SeqNumber {
        match self {
            BufferPacket::Lost(LostPacket {
                data_sequence_number: seq_number,
                ..
            })
            | BufferPacket::Dropped(seq_number)
            | BufferPacket::Received(DataPacket { seq_number, .. }) => *seq_number,
        }
    }

    pub fn data_packet(&self) -> Option<&DataPacket> {
        match self {
            BufferPacket::Received(data) => Some(data),
            _ => None,
        }
    }

    pub fn into_data_packet(self) -> Option<DataPacket> {
        match self {
            BufferPacket::Received(data) => Some(data),
            _ => None,
        }
    }

    pub fn in_message(&self, message: MsgNumber) -> bool {
        self.data_packet()
            .map_or(false, |d| d.message_number == message)
    }

    pub fn is_first(&self) -> bool {
        match self {
            BufferPacket::Received(data) if data.message_loc.contains(PacketLocation::FIRST) => {
                true
            }
            _ => false,
        }
    }

    fn lost_or_dropped(&self) -> Option<SeqNumber> {
        match self {
            BufferPacket::Lost(LostPacket {
                data_sequence_number: sn,
                ..
            })
            | BufferPacket::Dropped(sn) => Some(*sn),
            _ => None,
        }
    }

    pub fn lost_ready_for_feedback_mut(
        &mut self,
        now: Instant,
        rtt_mean: TimeSpan,
    ) -> Option<&mut LostPacket> {
        match self {
            BufferPacket::Lost(lost) if now > lost.feedback_time + (rtt_mean * lost.k) => {
                Some(lost)
            }
            _ => None,
        }
    }

    pub fn update_data(&mut self, data: DataPacket) -> Result<(), DataPacketError> {
        use BufferPacket::*;
        if matches!(self, Lost(_)) {
            *self = Received(data);
            Ok(())
        } else {
            Err(DataPacketError::DiscardedDuplicate {
                seq_number: data.seq_number,
            })
        }
    }

    pub fn drop_unreceived(&mut self) -> Option<SeqNumber> {
        use BufferPacket::*;
        let dsn = self.data_sequence_number();
        if matches!(self, Lost(_)) {
            *self = Dropped(dsn);
            Some(dsn)
        } else {
            None
        }
    }
}

pub struct MessagePacketCount {
    count: usize,
    done: bool,
}

impl MessagePacketCount {
    pub fn new() -> Self {
        Self {
            count: 0,
            done: false,
        }
    }

    pub fn accumulate(mut self, packet: &BufferPacket) -> Option<Self> {
        let location = packet.data_packet()?.message_loc;
        if !self.done {
            if self.count == 0 && !location.contains(PacketLocation::FIRST) {
                return None;
            }
            if location.contains(PacketLocation::LAST) {
                self.done = true;
            }
            self.count += 1;
        }
        Some(self)
    }

    pub fn calculate(self) -> Option<usize> {
        if self.done {
            Some(self.count)
        } else {
            None
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MessageError {
    pub too_late_packets: Range<SeqNumber>,
    pub delay: TimeSpan,
}

#[derive(Debug)]
pub struct ReceiveBuffer {
    tsbpd_latency: Duration,

    // Sequence number that all packets up to have been received + 1
    lrsn: SeqNumber,

    // first sequence number in the list
    seqno0: SeqNumber,

    remote_clock: SynchronizedRemoteClock,
    buffer: VecDeque<BufferPacket>,
    max_buffer_size: PacketCount,
}

impl ReceiveBuffer {
    pub fn new(
        socket_start_time: Instant,
        tsbpd_latency: Duration,
        init_seq_num: SeqNumber,
        max_buffer_size: PacketCount,
    ) -> Self {
        Self {
            tsbpd_latency,
            lrsn: init_seq_num,
            seqno0: init_seq_num,
            remote_clock: SynchronizedRemoteClock::new(socket_start_time),
            buffer: VecDeque::with_capacity(max_buffer_size.into()),
            max_buffer_size,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn next_ack_dsn(&self) -> SeqNumber {
        self.lrsn
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn synchronize_clock(
        &mut self,
        now: Instant,
        now_ts: TimeStamp,
    ) -> Option<ClockAdjustment> {
        self.remote_clock.synchronize(now, now_ts)
    }

    /// Buffer available, in packets
    pub fn buffer_available(&self) -> usize {
        usize::from(self.max_buffer_size) - self.buffer.len()
    }

    // next expected packet (1 + last received packet)
    fn next_packet_dsn(&self) -> SeqNumber {
        self.seqno0 + u32::try_from(self.buffer.len()).unwrap()
    }

    // index in buffer for a given sequence number
    // returns None if before the start of the buffer. Might return a index out of bounds
    fn index_for_seqno(&self, seq_number: SeqNumber) -> Option<usize> {
        if seq_number < self.seqno0 {
            None
        } else {
            Some((seq_number - self.seqno0) as usize)
        }
    }

    // index in buffer for a given sequence number clamped to 0 or buffer.len()
    fn clamped_index_for_seqno(&self, seq_number: SeqNumber) -> usize {
        min(seq_number.saturating_sub(self.seqno0), self.buffer.len())
    }

    pub fn push_packet(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        use std::cmp::Ordering::*;
        match data.seq_number.cmp(&self.next_packet_dsn()) {
            Equal => self.append_next(data),
            Greater => self.append_with_loss(now, data),
            Less => self.recover_data(data),
        }
    }

    pub fn pop_next_message(
        &mut self,
        now: Instant,
    ) -> Result<Option<(Instant, Bytes)>, MessageError> {
        let timestamp = match self.front_ts() {
            Some(timestamp) => timestamp,
            None => {
                return match self.drop_too_late_packets(now) {
                    Some(error) => Err(error),
                    None => Ok(None),
                }
            }
        };

        let sent_time = self.remote_clock.instant_from(timestamp);
        if now < sent_time + self.tsbpd_latency {
            return Ok(None);
        }

        let packet_count = match self.next_message_packet_count() {
            Some(packet_count) => packet_count,
            None => {
                return match self.drop_too_late_packets(now) {
                    Some(error) => Err(error),
                    None => Ok(None),
                }
            }
        };

        self.seqno0 += u32::try_from(packet_count).unwrap();

        let release_time = self.remote_clock.monotonic_instant_from(timestamp);
        let message = if packet_count == 1 {
            self.release_single_packet_message(release_time)
        } else {
            self.release_full_message(release_time, packet_count)
        };
        Ok(message)
    }

    fn front_ts(&mut self) -> Option<TimeStamp> {
        self.buffer.front()?.data_packet().map(|d| d.timestamp)
    }

    fn release_single_packet_message(&mut self, release_time: Instant) -> Option<(Instant, Bytes)> {
        Some((
            release_time,
            self.buffer.pop_front()?.into_data_packet()?.payload,
        ))
    }

    fn release_full_message(
        &mut self,
        release_time: Instant,
        packet_count: usize,
    ) -> Option<(Instant, Bytes)> {
        Some((
            release_time,
            self.buffer
                .drain(0..packet_count)
                .fold(BytesMut::new(), |mut bytes, pack| {
                    bytes.extend(pack.into_data_packet().unwrap().payload);
                    bytes
                })
                .freeze(),
        ))
    }

    pub fn prepare_loss_list(
        &mut self,
        now: Instant,
        rtt_mean: TimeSpan,
    ) -> Option<CompressedLossList> {
        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.
        let loss_list = self
            .buffer
            .range_mut(self.lost_list_index()..)
            .filter_map(|p| p.lost_ready_for_feedback_mut(now, rtt_mean))
            .map(|lost| {
                // increment k and change feedback time, returning sequence numbers
                lost.k += 1;
                lost.feedback_time = now;
                lost.data_sequence_number
            });

        CompressedLossList::try_from_iter(loss_list)
    }

    /// Returns how many packets were actually dropped
    pub fn drop_packets(&mut self, range: Range<SeqNumber>) -> usize {
        // if start of the range has been dropped already, just drop everything after
        let first_idx = self.clamped_index_for_seqno(range.start);
        let last_idx = self.clamped_index_for_seqno(range.end);
        self.buffer
            .range_mut(first_idx..last_idx)
            .filter_map(|p| p.drop_unreceived())
            .count()
    }

    pub fn next_message_release_time(&self) -> Option<Instant> {
        self.buffer
            .front()
            .filter(|p| p.is_first())?
            .data_packet()
            .map(|d| self.remote_clock.instant_from(d.timestamp) + self.tsbpd_latency)
    }

    fn append_next(&mut self, data: DataPacket) -> Result<DataPacketAction, DataPacketError> {
        if self.buffer_available() == 0 {
            Err(DataPacketError::BufferFull {
                seq_number: data.seq_number,
                buffer_size: self.buffer.len(),
            })
        } else {
            self.append_data(data);
            Ok(DataPacketAction::Received {
                lrsn: self.lrsn,
                recovered: false,
            })
        }
    }

    fn append_with_loss(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        let seq_number = data.seq_number;
        let lost = self.next_packet_dsn()..seq_number;
        let lost_count = lost.end - lost.start;

        // avoid buffer overrun
        let buffer_required = usize::try_from(lost_count).unwrap() + 1; // +1 to store the packet itself
        let buffer_available = self.buffer_available();
        if buffer_available < buffer_required {
            Err(DataPacketError::PacketTooEarly {
                seq_number,
                buffer_available,
                buffer_required,
            })
        } else {
            self.append_lost_packets(now, &lost);
            self.append_data(data);
            Ok(DataPacketAction::ReceivedWithLoss(lost.into()))
        }
    }

    fn recover_data(&mut self, data: DataPacket) -> Result<DataPacketAction, DataPacketError> {
        let seq_number = data.seq_number;
        let index = self
            .index_for_seqno(seq_number)
            .ok_or(DataPacketError::PacketTooLate {
                seq_number,
                seq_number_0: self.seqno0,
            })?;

        self.buffer.get_mut(index).unwrap().update_data(data)?;

        // first lost packet was recovered, update LRSN
        if self.lrsn == seq_number {
            self.recalculate_lrsn(index);
        }
        Ok(DataPacketAction::Received {
            lrsn: self.lrsn,
            recovered: true,
        })
    }

    fn append_data(&mut self, data: DataPacket) {
        let seq_number = data.seq_number;
        if self.lrsn == seq_number {
            self.lrsn = seq_number + 1;
        }
        self.buffer.push_back(BufferPacket::Received(data));
    }

    fn append_lost_packets(&mut self, now: Instant, lost: &Range<SeqNumber>) {
        let lost_count = lost.end - lost.start;
        for i in 0..lost_count {
            let loss = LostPacket::new(lost.start + i, now);
            self.buffer.push_back(BufferPacket::Lost(loss));
        }
    }

    fn lost_list_index(&self) -> usize {
        self.buffer
            .iter()
            .take_while(|b| b.data_packet().is_some())
            .count()
    }

    fn next_message_packet_count(&self) -> Option<usize> {
        let first = self.buffer.front()?.data_packet()?;
        self.buffer
            .iter()
            // once stabilized in std, take_while & filter_map can be replaced with map_while
            .take_while(|p| p.in_message(first.message_number))
            .try_fold(MessagePacketCount::new(), |a, p| a.accumulate(p))?
            .calculate()
    }

    /// Drops the packets that are deemed to be too late
    /// i.e.: there is a packet after it that is ready to be released
    fn drop_too_late_packets(&mut self, now: Instant) -> Option<MessageError> {
        let latency_window = self.tsbpd_latency + Duration::from_millis(5);
        // Not only does it have to be non-none, it also has to be a First (don't drop half messages)
        let (index, seq_number, timestamp) = self
            .buffer
            .iter()
            .enumerate()
            .skip(1)
            .take_until(|(_, p)| p.is_first())
            .last()
            .and_then(|(i, p)| {
                p.data_packet()
                    .map(|d| (i, d.seq_number, self.remote_clock.instant_from(d.timestamp)))
            })
            .filter(|(_, _, timestamp)| now >= *timestamp + latency_window)?;

        let delay = TimeSpan::from_interval(timestamp + self.tsbpd_latency, now);
        let drop_count = self.buffer.drain(0..index).count();

        self.seqno0 = seq_number;
        self.recalculate_lrsn(0);

        Some(MessageError {
            too_late_packets: seq_number - drop_count as u32..seq_number,
            delay,
        })
    }

    fn recalculate_lrsn(&mut self, start_idx: usize) {
        self.lrsn = self
            .buffer
            .range(start_idx..)
            .filter_map(|p| p.lost_or_dropped())
            .next()
            .unwrap_or_else(|| self.next_packet_dsn())
    }

    pub fn rx_acknowledged_time(&self) -> Duration {
        let start_idx = 0;
        let end_idx = self.clamped_index_for_seqno(self.lrsn - 1);

        if let (Some(BufferPacket::Received(s)), Some(BufferPacket::Received(e))) =
            (self.buffer.get(start_idx), self.buffer.get(end_idx))
        {
            Duration::from_micros(
                u64::try_from((e.timestamp - s.timestamp).as_micros()).unwrap_or(0),
            )
        } else {
            Duration::from_micros(0)
        }
    }
}

#[cfg(test)]
mod receive_buffer {
    use super::*;

    use DataPacketAction::*;
    use DataPacketError::*;

    fn basic_pack() -> DataPacket {
        DataPacket {
            seq_number: SeqNumber(1),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: MsgNumber(0),
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(4),
            payload: Bytes::new(),
        }
    }

    #[test]
    fn not_ready_empty() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(3);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start), Ok(None));
    }

    #[test]
    fn multi_packet_message_not_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), Ok(None));
    }

    #[test]
    fn multi_packet_message_lost_last_packet() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), Ok(None));

        // 1 lost packet
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss([SeqNumber(6)].iter().collect()))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Err(MessageError {
                too_late_packets: SeqNumber(5)..SeqNumber(7),
                delay: TimeSpan::from_millis(2_000)
            })
        );
    }

    #[test]
    fn multi_packet_message_incomplete_transmission() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), Ok(None));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));
    }

    #[test]
    fn single_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST | PacketLocation::LAST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    payload: b"no"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Ok(Some((start, b"hello"[..].into())))
        );
    }

    #[test]
    fn push_packet_with_loss_empty_buffer() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    message_loc: PacketLocation::MIDDLE,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss((init_seq_num..init_seq_num + 2).into()))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));
    }

    #[test]
    fn push_packet_multi_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    message_loc: PacketLocation::LAST,
                    payload: b"nas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 3,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 3);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start), Ok(None));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Ok(Some((start, b"helloyasnas"[..].into())))
        );

        assert_eq!(buf.buffer.len(), 0);
    }

    #[test]
    fn prepare_loss_list() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        assert_eq!(buf.prepare_loss_list(start, mean_rtt), None);

        let now = start;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 5,
                    message_loc: PacketLocation::LAST,
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 1..init_seq_num + 5).into()
            ))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 15,
                    message_loc: PacketLocation::LAST,
                    payload: b"nas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 6..init_seq_num + 15).into()
            ))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt * 3;
        assert_eq!(
            buf.prepare_loss_list(now, mean_rtt),
            Some((1..5).chain(6..15).map(|a| init_seq_num + a).collect())
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn drop_too_late_packets() {
        let _ = pretty_env_logger::try_init();

        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        let now = start;
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 1,
                message_loc: PacketLocation::FIRST,
                payload: b"hello"[..].into(),
                ..basic_pack()
            },
        );
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 2,
                message_loc: PacketLocation::MIDDLE,
                payload: b"hello"[..].into(),
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        let now = now + tsbpd;
        let expected_release_time = now;
        let _ = buf.push_packet(
            now,
            DataPacket {
                timestamp: TimeStamp::MIN + tsbpd,
                seq_number: init_seq_num + 5,
                message_loc: PacketLocation::ONLY,
                payload: b"yas"[..].into(),
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + Duration::from_millis(5);
        // it should drop all missing packets up to the next viable message
        // and begin to ack all viable packets
        assert_eq!(
            buf.pop_next_message(now),
            Err(MessageError {
                too_late_packets: SeqNumber(5)..SeqNumber(6),
                delay: TimeSpan::from_millis(5)
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 3, "{buf:?}");

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + tsbpd + Duration::from_millis(5);
        // it should drop all missing packets up to the next viable message
        // and begin to ack all viable packets
        assert_eq!(
            buf.pop_next_message(now),
            Err(MessageError {
                too_late_packets: SeqNumber(6)..SeqNumber(10),
                delay: TimeSpan::from_millis(10)
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 6);

        assert_eq!(
            buf.pop_next_message(now),
            Ok(Some((expected_release_time, b"yas"[..].into())))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 6);
    }

    #[test]
    fn drop_message() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        let now = start;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 3,
                    message_loc: PacketLocation::LAST,
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss((init_seq_num..init_seq_num + 3).into()))
        );

        // fully out of bounds
        assert_eq!(buf.drop_packets(init_seq_num + 9..init_seq_num + 12), 0);

        // only drop packets that are marked Lost, i.e. pending NAK
        assert_eq!(buf.drop_packets(init_seq_num - 1..init_seq_num + 5), 3);

        // no longer schedule the dropped packets for NAK
        let now = now + mean_rtt * 3;
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn buffer_sizing() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(10));

        assert_eq!(buf.buffer_available(), 10);

        // in order, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 9);

        // normal, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 8,
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 1..init_seq_num + 8).into()
            ))
        );
        assert_eq!(buf.buffer_available(), 1);

        // past end, overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Err(PacketTooEarly {
                seq_number: init_seq_num + 10,
                buffer_available: 1,
                buffer_required: 2
            })
        );
        assert_eq!(buf.buffer_available(), 1);

        // normal, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 9,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 0);

        // past end, overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Err(BufferFull {
                seq_number: init_seq_num + 10,
                buffer_size: 10
            })
        );
        assert_eq!(buf.buffer_available(), 0);

        // make room for last packetx
        buf.pop_next_message(start + tsbpd).unwrap();
        assert_eq!(buf.buffer_available(), 1);

        // should work this time
        assert_eq!(
            buf.push_packet(
                start + tsbpd,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 0);
    }

    #[test]
    fn wrong_lrsn_after_drop_all() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(8192));

        let now = start;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 3,
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss((init_seq_num..init_seq_num + 3).into()))
        );

        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        // pop_next_message is strange, may want some cleanup
        assert_eq!(
            buf.pop_next_message(now + tsbpd + Duration::from_millis(10)),
            Err(MessageError {
                too_late_packets: SeqNumber(5)..SeqNumber(8),
                delay: TimeSpan::from_millis(10)
            })
        );
        assert_eq!(
            buf.pop_next_message(now + tsbpd + Duration::from_millis(10)),
            Ok(Some((now, b"yas"[..].into())))
        );

        assert_eq!(buf.next_ack_dsn(), init_seq_num + 4);
    }

    #[test]
    fn rx_acknowledged_time() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, PacketCount(10));

        let add_packet = |i, buf: &mut ReceiveBuffer| {
            buf.push_packet(
                start + Duration::from_micros(u64::from(i) * 10),
                DataPacket {
                    seq_number: init_seq_num + i,
                    timestamp: TimeStamp::from_micros(i * 10),
                    ..basic_pack()
                },
            )
            .unwrap();
        };

        assert_eq!(buf.rx_acknowledged_time(), Duration::from_secs(0));

        add_packet(0, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_secs(0));

        // in order, increases rx_acknowledged_time
        add_packet(1, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        // out of order, no change
        add_packet(3, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        // got missing paket, goes up
        add_packet(2, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(30));

        // pop packets
        buf.pop_next_message(start + tsbpd + Duration::from_micros(10))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(20));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(20))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(30))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(40))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));

        assert_eq!(
            buf.pop_next_message(start + tsbpd + Duration::from_micros(40))
                .unwrap(),
            None
        );
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));
    }
}
