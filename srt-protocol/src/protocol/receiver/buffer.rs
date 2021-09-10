use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use log::info;
use take_until::TakeUntilExt;

use crate::packet::{CompressedLossList, PacketLocation};
use crate::protocol::receiver::time::SynchronizedRemoteClock;
use crate::protocol::{TimeSpan, TimeStamp};
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
}

impl BufferPacket {
    pub fn data_sequence_number(&self) -> SeqNumber {
        match self {
            BufferPacket::Lost(LostPacket {
                data_sequence_number,
                ..
            }) => *data_sequence_number,
            BufferPacket::Received(DataPacket { seq_number, .. }) => *seq_number,
        }
    }

    pub fn data_packet(&self) -> Option<&DataPacket> {
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

    pub fn update_data(
        &mut self,
        data: DataPacket,
    ) -> Result<Option<CompressedLossList>, DataPacket> {
        use BufferPacket::*;
        if matches!(self, Lost(_)) {
            *self = Received(data);
            Ok(None)
        } else {
            Ok(None)
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
    lrsn: SeqNumber,
    next_packet_dsn: SeqNumber,
    remote_clock: SynchronizedRemoteClock,
    buffer: VecDeque<BufferPacket>,
}

impl ReceiveBuffer {
    pub fn new(
        socket_start_time: Instant,
        tsbpd_latency: Duration,
        init_seq_num: SeqNumber,
    ) -> Self {
        Self {
            tsbpd_latency,
            lrsn: init_seq_num,
            next_packet_dsn: init_seq_num,
            remote_clock: SynchronizedRemoteClock::new(socket_start_time),
            buffer: VecDeque::new(),
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

    pub fn push_packet(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<Option<CompressedLossList>, DataPacket> {
        use std::cmp::Ordering::*;
        match data.seq_number.cmp(&self.next_packet_dsn) {
            Equal => {
                self.append_data(data);
                Ok(None)
            }
            Greater => {
                let loss_list = self.calculate_loss_list(now, data.seq_number);
                self.append_data(data);
                Ok(loss_list)
            }
            Less => self.recover_data(data),
        }
    }

    fn recover_data(&mut self, data: DataPacket) -> Result<Option<CompressedLossList>, DataPacket> {
        let d = &data;
        let front = self.buffer.front();

        if front.is_none() {
            return Ok(None);
        }

        let front = front
            .map(|p| p.data_sequence_number())
            .filter(|front| *front < d.seq_number);

        if front.is_none() {
            return Ok(None);
        }

        let index = data.seq_number - front.unwrap();
        self.buffer
            .get_mut(index as usize)
            .expect("invalid index")
            .update_data(data)
    }

    fn calculate_loss_list(&mut self, now: Instant, end: SeqNumber) -> Option<CompressedLossList> {
        let begin = self.next_packet_dsn;
        if end <= begin {
            return None;
        }

        let count = end - begin;
        let lost = (0..count).map(|n| {
            let seq_num = begin + n;
            self.buffer
                .push_back(BufferPacket::Lost(LostPacket::new(seq_num, now)));
            seq_num
        });

        CompressedLossList::try_from(lost)
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
                self.buffer.pop_front()?.data_packet()?.payload.clone(),
            ));
        }

        // accumulate the rest
        Some((
            release_time,
            self.buffer
                .drain(0..packet_count?)
                .fold(BytesMut::new(), |mut bytes, pack| {
                    bytes.extend(pack.data_packet().unwrap().payload.clone());
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

    /// Drops the packets that are deemed to be too late
    /// IE: there is a packet after it that is ready to be released
    ///
    /// Returns the number of packets dropped
    pub fn drop_too_late_packets(
        &mut self,
        now: Instant,
    ) -> Option<(SeqNumber, SeqNumber, TimeSpan)> {
        let latency_tolerance = self.tsbpd_latency + Duration::from_millis(5);
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
            .filter(|(_, _, timestamp)| now >= *timestamp + latency_tolerance)?;

        let latency = TimeSpan::from_interval(timestamp + self.tsbpd_latency, now);
        let drop_count = self.buffer.drain(0..index).count();
        self.lrsn = self.calculate_lrsn();

        info!(
            "Receiver dropping packets: [{},{}), {:?} too late",
            seq_number - drop_count as u32,
            seq_number,
            latency
        );

        Some((seq_number - drop_count as u32, seq_number, latency))
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
        self.buffer.push_back(BufferPacket::Received(data));

        self.next_packet_dsn = seq_number + 1;
        if self.lrsn == seq_number {
            self.lrsn = seq_number + 1;
        } else {
            self.lrsn = self.calculate_lrsn();
        }
    }

    fn calculate_lrsn(&mut self) -> SeqNumber {
        self.buffer
            .range(self.lost_list_index()..)
            .filter_map(|p| p.lost_list())
            .next()
            .unwrap_or(self.next_packet_dsn)
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
            message_loc: PacketLocation::FIRST,
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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start), None);
    }

    #[test]
    fn multi_packet_message_not_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);
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
                init_seq_num + 1
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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);
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

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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
                init_seq_num + 4
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
                init_seq_num + 14
            )))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt * 3;
        assert_eq!(
            buf.prepare_loss_list(now, mean_rtt),
            CompressedLossList::try_from(
                seq_num_range(init_seq_num + 1, init_seq_num + 4)
                    .chain(seq_num_range(init_seq_num + 6, init_seq_num + 14))
            )
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn drop_too_late_packets() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, init_seq_num);

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
}
