use std::{
    collections::VecDeque,
    convert::TryFrom,
    ops::Range,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use log::{info, warn};
use take_until::TakeUntilExt;

use crate::protocol::receiver::time::SynchronizedRemoteClock;
use crate::protocol::{TimeSpan, TimeStamp};
use crate::{
    packet::{CompressedLossList, PacketLocation},
    seq_number::seq_num_range,
};
use crate::{DataPacket, MsgNumber, SeqNumber};

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

    pub fn lost_list(&self) -> Option<SeqNumber> {
        match self {
            BufferPacket::Lost(lost) => Some(lost.data_sequence_number),
            _ => None,
        }
    }

    pub fn lost_ready_for_feeback_mut(
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

    pub fn update_data(&mut self, data: DataPacket) {
        use BufferPacket::*;
        if matches!(self, Lost(_)) {
            *self = Received(data);
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

#[derive(Debug)]
pub struct ReceiveBuffer {
    tsbpd_latency: Duration,

    // Sequence number that all packets up to have been received + 1
    lrsn: SeqNumber,

    remote_clock: SynchronizedRemoteClock,
    buffer: VecDeque<BufferPacket>,
    max_buffer_size: usize,
}

impl ReceiveBuffer {
    pub fn new(
        socket_start_time: Instant,
        tsbpd_latency: Duration,
        init_seq_num: SeqNumber,
        max_buffer_size: usize,
    ) -> Self {
        Self {
            tsbpd_latency,
            lrsn: init_seq_num,
            remote_clock: SynchronizedRemoteClock::new(socket_start_time),
            buffer: VecDeque::with_capacity(max_buffer_size),
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

    pub fn synchronize_clock(&mut self, now: Instant, now_ts: TimeStamp) {
        self.remote_clock.synchronize(now, now_ts);
    }

    /// Buffer available, in packets
    pub fn buffer_available(&self) -> usize {
        self.max_buffer_size - self.buffer.len()
    }

    // next expected packet (1 + last received packet)
    fn next_packet_dsn(&self) -> SeqNumber {
        self.seqno0() + u32::try_from(self.buffer.len()).unwrap()
    }

    // sequence number of the first packet in the buffer
    fn seqno0(&self) -> SeqNumber {
        match self.buffer.front() {
            Some(bp) => bp.data_sequence_number(),
            None => self.lrsn,
        }
    }

    // index in buffer for a given sequence number
    // returns None if before the start of the buffer. Might return a index out of bounds
    fn index_for_seqno(&self, s: SeqNumber) -> Option<usize> {
        let seqno0 = self.seqno0();
        if s < seqno0 {
            None
        } else {
            Some(usize::try_from(s - seqno0).unwrap())
        }
    }

    pub fn push_packet(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<Option<CompressedLossList>, DataPacket> {
        use std::cmp::Ordering::*;
        match data.seq_number.cmp(&self.next_packet_dsn()) {
            Equal => {
                self.append_data(data);
                Ok(None)
            }
            Greater => {
                let begin_lost = self.next_packet_dsn();
                let end_lost = data.seq_number;

                // avoid buffer overrun
                let buffer_required = usize::try_from(end_lost - begin_lost).unwrap() + 1; // +1 to store the packet itsself
                if self.buffer_available() < buffer_required {
                    warn!(
                        "Packet received too far in the future for configured receive buffer size. Discarding packet (buffer would need to be {} packets larger)", 
                        buffer_required - self.buffer_available()
                    );
                    return Ok(None);
                }

                // append lost packets to end
                self.buffer.extend(
                    seq_num_range(begin_lost, end_lost)
                        .map(|s| BufferPacket::Lost(LostPacket::new(s, now))),
                );

                self.append_data(data);

                Ok(CompressedLossList::try_from(seq_num_range(
                    begin_lost, end_lost,
                )))
            }
            Less => {
                self.recover_data(data);
                Ok(None)
            }
        }
    }

    pub fn pop_next_message(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        let timestamp = self.buffer.front()?.data_packet().map(|d| d.timestamp);
        if timestamp.is_none() {
            // TODO: do something with results
            let _ = self.drop_too_late_packets(now);
            return None;
        }

        let sent_time = self.remote_clock.instant_from(timestamp?);
        if now < sent_time + self.tsbpd_latency {
            return None;
        }

        let packet_count = self.next_message_packet_count();
        if packet_count.is_none() {
            // TODO: do something with results
            let _ = self.drop_too_late_packets(now);
            return None;
        }

        let release_time = self.remote_clock.monotonic_instant_from(timestamp?);
        // optimize for single packet messages
        if packet_count? == 1 {
            return Some((
                release_time,
                self.buffer.pop_front()?.into_data_packet()?.payload,
            ));
        }

        // accumulate the rest
        Some((
            release_time,
            self.buffer
                .drain(0..packet_count?)
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
            .filter_map(|p| p.lost_ready_for_feeback_mut(now, rtt_mean))
            .map(|lost| {
                // increment k and change feedback time, returning sequence numbers
                lost.k += 1;
                lost.feedback_time = now;
                lost.data_sequence_number
            });

        CompressedLossList::try_from(loss_list)
    }

    /// Returns how many packets were actually dropped
    pub fn drop_message(&mut self, range: Range<SeqNumber>) -> usize {
        use std::cmp::min;

        let first_idx = self.index_for_seqno(range.start).unwrap_or(0); // if start of the range has been dropped already, just drop everything after

        // clamp to end
        let last_idx = min(
            self.buffer.len(),
            self.index_for_seqno(range.end).unwrap_or(0),
        );

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

    fn append_data(&mut self, data: DataPacket) {
        let seq_number = data.seq_number;
        if self.buffer_available() == 0 {
            warn!("Dropping packet {}, receive buffer full", data.seq_number);
            return;
        }

        assert_eq!(self.index_for_seqno(seq_number), Some(self.buffer.len()));

        self.buffer.push_back(BufferPacket::Received(data));

        if self.lrsn == seq_number {
            self.lrsn = seq_number + 1;
        } else {
            self.lrsn = self.calculate_lrsn();
        }
    }

    fn calculate_lrsn(&self) -> SeqNumber {
        self.buffer
            .range(self.lost_list_index()..)
            .filter_map(|p| p.lost_list())
            .next()
            .unwrap_or_else(|| self.next_packet_dsn())
    }

    fn lost_list_index(&self) -> usize {
        self.buffer.front().map_or(0, |p| {
            let front = p.data_sequence_number();
            (std::cmp::max(front, self.lrsn) - front) as usize
        })
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

    fn recover_data(&mut self, data: DataPacket) {
        match self.index_for_seqno(data.seq_number) {
            Some(idx) if idx < self.buffer.len() => {
                self.buffer.get_mut(idx).unwrap().update_data(data);
            }
            _ => {}
        }
    }

    /// Drops the packets that are deemed to be too late
    /// i.e.: there is a packet after it that is ready to be released
    fn drop_too_late_packets(&mut self, now: Instant) -> Option<(SeqNumber, SeqNumber, TimeSpan)> {
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
        self.lrsn = self.calculate_lrsn();

        info!(
            "Receiver dropping packets: [{},{}), {:?} too late",
            seq_number - drop_count as u32,
            seq_number,
            delay
        );

        Some((seq_number - drop_count as u32, seq_number - 1, delay))
    }
}

#[cfg(test)]
mod receive_buffer {
    use super::*;
    use crate::packet::{CompressedLossList, DataEncryption};
    use crate::seq_number::seq_num_range;
    use crate::{MsgNumber, SocketId};

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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start), None);
    }

    #[test]
    fn multi_packet_message_not_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), None);
    }

    #[test]
    fn multi_packet_message_lost_last_packet() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), None);

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
            Ok(CompressedLossList::try_from(vec![SeqNumber(6)].into_iter()))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), None);
    }

    #[test]
    fn multi_packet_message_incomplete_transmission() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd * 2), None);

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    ..basic_pack()
                }
            ),
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), None);
    }

    #[test]
    fn single_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

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
            Ok(None)
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
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Some((start, b"hello"[..].into()))
        );
    }

    #[test]
    fn push_packet_with_loss_empty_buffer() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);
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
            Ok(CompressedLossList::try_from(seq_num_range(
                init_seq_num,
                init_seq_num + 2
            )))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start + tsbpd), None);
    }

    #[test]
    fn push_packet_multi_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);
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
            Ok(None)
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
            Ok(None)
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
            Ok(None)
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 3);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start), None);
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Some((start, b"helloyasnas"[..].into()))
        );

        assert_eq!(buf.buffer.len(), 0);
    }

    #[test]
    fn prepare_loss_list() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

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
            Ok(None)
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
            Ok(CompressedLossList::try_from(seq_num_range(
                init_seq_num + 1,
                init_seq_num + 5
            )))
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
            Ok(CompressedLossList::try_from(seq_num_range(
                init_seq_num + 6,
                init_seq_num + 15
            )))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt * 3;
        assert_eq!(
            buf.prepare_loss_list(now, mean_rtt),
            CompressedLossList::try_from(
                seq_num_range(init_seq_num + 1, init_seq_num + 5)
                    .chain(seq_num_range(init_seq_num + 6, init_seq_num + 15))
            )
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn drop_too_late_packets() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

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
        assert_eq!(buf.pop_next_message(now), None);
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
        assert_eq!(buf.pop_next_message(now), None);
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + Duration::from_millis(5);
        assert_eq!(buf.pop_next_message(now), None);
        // it should drop all missing packets up to the next viable message
        // and begin to ack all viable packets
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 3);

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + tsbpd + Duration::from_millis(5);
        assert_eq!(buf.pop_next_message(now), None);
        // it should drop all missing packets up to the next viable message
        // and begin to ack all viable packets
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 6);

        assert_eq!(
            buf.pop_next_message(now),
            Some((expected_release_time, b"yas"[..].into()))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 6);
    }

    #[test]
    fn drop_message() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 8192);

        let now = start;
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 3,
                message_loc: PacketLocation::LAST,
                payload: b"yas"[..].into(),
                ..basic_pack()
            },
        );

        // only drop packets that are marked Lost, i.e. pending NAK
        assert_eq!(
            buf.drop_message(Range {
                start: init_seq_num - 1,
                end: init_seq_num + 5
            }),
            3
        );

        // no longer schedule the dropped packets for NAK
        let now = now + mean_rtt * 3;
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn buffer_sizing() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num, 10);

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
            Ok(None)
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
            Ok(Some(CompressedLossList::from_loss_list(seq_num_range(
                init_seq_num + 1,
                init_seq_num + 8
            ))))
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
            Ok(None)
        );

        assert_eq!(buf.buffer_available(), 1);

        // make room for last packet
        buf.pop_next_message(start + tsbpd).unwrap();

        assert_eq!(buf.buffer_available(), 2);

        // should work this time
        assert_eq!(
            buf.push_packet(
                start + tsbpd,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Ok(Some(CompressedLossList::from_loss_list(seq_num_range(
                init_seq_num + 9,
                init_seq_num + 10
            ))))
        );

        assert_eq!(buf.buffer_available(), 0);
    }
}
