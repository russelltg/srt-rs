use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use log::{debug, info};

use crate::packet::PacketLocation;
use crate::protocol::{TimeBase, TimeStamp};
use crate::{ConnectionSettings, DataPacket, SeqNumber, SocketID};

pub struct RecvBuffer {
    // stores the incoming packets as they arrive
    // `buffer[0]` will hold sequence number `head`
    buffer: VecDeque<Option<DataPacket>>,

    // The next to be released sequence number
    head: SeqNumber,

    time_base: TimeBase,

    /// The TSBPD latency configured by the user.
    /// Not necessarily the actual decided on latency, which
    /// is the max of both side's respective latencies.
    tsbpd_latency: Duration,

    local_sockid: SocketID,
}

impl RecvBuffer {
    pub fn with(settings: &ConnectionSettings) -> Self {
        Self::new(
            settings.init_seq_num,
            TimeBase::from_raw(settings.socket_start_time),
            settings.tsbpd_latency,
            settings.local_sockid,
        )
    }

    /// Creates a `RecvBuffer`
    ///
    /// * `head` - The sequence number of the next packet
    pub fn new(
        head: SeqNumber,
        time_base: TimeBase,
        tsbpd_latency: Duration,
        local_sockid: SocketID,
    ) -> Self {
        Self {
            buffer: VecDeque::new(),
            head,
            time_base,
            tsbpd_latency,
            local_sockid,
        }
    }

    /// The next to be released sequence number
    pub fn next_release(&self) -> SeqNumber {
        self.head
    }

    /// Adds a packet to the buffer
    /// If `pack.seq_number < self.head`, this is nop (ie it appears before an already released packet)
    pub fn add(&mut self, pack: DataPacket) {
        if pack.seq_number < self.head {
            return; // packet is too late
        }

        // resize `buffer` if necessary
        let idx = (pack.seq_number - self.head) as usize;
        if idx >= self.buffer.len() {
            self.buffer.resize(idx + 1, None);
        }

        // add the new element
        self.buffer[idx] = Some(pack)
    }

    /// Drops the packets that are deemed to be too late
    /// IE: there is a packet after it that is ready to be released
    ///
    /// Returns the number of packets dropped
    pub fn drop_too_late_packets(&mut self, now: Instant) -> usize {
        // Not only does it have to be non-none, it also has to be a First (don't drop half messages)
        let first_non_none_idx = self.buffer.iter().position(|a| {
            a.is_some()
                && a.as_ref()
                    .unwrap()
                    .message_loc
                    .contains(PacketLocation::FIRST)
        });

        let first_non_none_idx = match first_non_none_idx {
            None | Some(0) => return 0, // even though some of these may be too late, there are none that can be released so they can't them back.
            Some(i) => i,
        };

        let first_pack_ts_us = self.buffer[first_non_none_idx].as_ref().unwrap().timestamp;
        // we are too late if that packet is ready
        // give a 2 ms buffer range, be ok with releasing them 2ms late
        let too_late = self.time_base.instant_from(first_pack_ts_us)
            + self.tsbpd_latency
            + Duration::from_millis(2)
            <= now;

        if too_late {
            info!(
                "Dropping packets [{},{}), {} ms too late",
                self.head,
                self.head + first_non_none_idx as u32,
                (now - self.time_base.instant_from(first_pack_ts_us) - self.tsbpd_latency)
                    .as_millis()
            );
            // start dropping packets
            self.head += first_non_none_idx as u32;
            self.buffer.drain(0..first_non_none_idx).count()
        } else {
            0 // the next available packet isn't ready to be sent yet
        }
    }

    /// Check if there is an available message to release with TSBPD
    /// ie - `start_time + timestamp + tsbpd <= now`
    ///
    /// * `latency` - The latency to release with
    /// * `start_time` - The start time of the socket to add to timestamps
    /// TODO: this does not account for timestamp wrapping
    ///
    /// Returns `None` if there is no message available, or `Some(i)` if there is a packet available, `i` being the number of packets it spans.
    pub fn next_msg_ready_tsbpd(&self, now: Instant) -> Option<usize> {
        let msg_size = self.next_msg_ready()?;

        let pack = self.buffer.front().unwrap().as_ref().unwrap();

        if self.time_base.instant_from(pack.timestamp) + self.tsbpd_latency <= now {
            debug!(
                "Message for {:?} was deemed ready for release, Now={:?}, Ts={:?}, dT={:?}, Latency={:?}, buf.len={}, sn={}, npackets={}",
                self.local_sockid,
                now - self.time_base.instant_from(0),
                Duration::from_micros(pack.timestamp as u64),
                now - self.time_base.instant_from(pack.timestamp),
                self.tsbpd_latency,
                self.buffer.len(),
                pack.seq_number,
                msg_size,
            );
            Some(msg_size)
        } else {
            None
        }
    }

    /// Check if the next message is available. Returns `None` if there is no message,
    /// and `Some(i)` if there is a message available, where `i` is the number of packets this message spans
    pub fn next_msg_ready(&self) -> Option<usize> {
        let first = self.buffer.front();
        if let Some(Some(first)) = first {
            // we have a first packet, make sure it has the start flag set
            assert!(
                first.message_loc.contains(PacketLocation::FIRST),
                "Packet seq={} was not marked as the first in it's message",
                first.seq_number
            );

            let mut count = 1;

            for i in &self.buffer {
                match i {
                    Some(ref pack) if pack.message_loc.contains(PacketLocation::LAST) => {
                        return Some(count)
                    }
                    None => return None,
                    _ => count += 1,
                }
            }
        }

        None
    }

    pub fn next_message_release_time(&self) -> Option<Instant> {
        let _msg_size = self.next_msg_ready()?;
        let timestamp = self.buffer.front()?.as_ref()?.timestamp;
        Some(self.time_base.instant_from(timestamp) + self.tsbpd_latency)
    }

    /// A convenience function for
    /// `self.next_msg_ready_tsbpd(...).map(|_| self.next_msg().unwrap()`
    pub fn next_msg_tsbpd(&mut self, now: Instant) -> Option<(Instant, Bytes)> {
        self.next_msg_ready_tsbpd(now)
            .map(|_| self.next_msg().unwrap())
    }

    /// Check if there is an available message, returning, and its origin timestamp it if found
    pub fn next_msg(&mut self) -> Option<(Instant, Bytes)> {
        let count = self.next_msg_ready()?;

        self.head += count as u32;

        let origin_time = self
            .time_base
            .instant_from(self.buffer[0].as_ref().unwrap().timestamp);

        // optimize for single packet messages
        if count == 1 {
            return Some((
                origin_time,
                self.buffer.pop_front().unwrap().unwrap().payload,
            ));
        }

        // accumulate the rest
        Some((
            origin_time,
            self.buffer
                .drain(0..count)
                .fold(BytesMut::new(), |mut bytes, pack| {
                    bytes.extend(pack.unwrap().payload);
                    bytes
                })
                .freeze(),
        ))
    }

    pub fn timestamp_from(&self, at: Instant) -> TimeStamp {
        self.time_base.timestamp_from(at)
    }
}

impl fmt::Debug for RecvBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{:?}",
            self.buffer
                .iter()
                .map(|o| o
                    .as_ref()
                    .map(|pack| (pack.seq_number.as_raw(), pack.message_loc)))
                .collect::<Vec<_>>()
        )
    }
}

#[cfg(test)]
mod test {

    use super::RecvBuffer;
    use crate::protocol::TimeBase;
    use crate::{packet::PacketLocation, DataPacket, MsgNumber, SeqNumber, SocketID};
    use bytes::Bytes;
    use std::time::Duration;

    fn basic_pack() -> DataPacket {
        DataPacket {
            seq_number: SeqNumber::new_truncate(5),
            message_loc: PacketLocation::FIRST,
            in_order_delivery: false,
            message_number: MsgNumber(0),
            timestamp: 0,
            dest_sockid: SocketID(4),
            payload: Bytes::new(),
        }
    }

    fn new_buffer(head: SeqNumber) -> RecvBuffer {
        RecvBuffer::new(
            head,
            TimeBase::new(),
            Duration::from_millis(100),
            rand::random(),
        )
    }

    #[test]
    fn not_ready_empty() {
        let mut buf = new_buffer(SeqNumber::new_truncate(3));

        assert_eq!(buf.next_msg_ready(), None);
        assert_eq!(buf.next_msg(), None);
        assert_eq!(buf.next_release(), SeqNumber(3));
    }

    #[test]
    fn not_ready_no_more() {
        let mut buf = new_buffer(SeqNumber::new_truncate(5));
        buf.add(DataPacket {
            seq_number: SeqNumber(5),
            message_loc: PacketLocation::FIRST,
            ..basic_pack()
        });

        assert_eq!(buf.next_msg_ready(), None);
        assert_eq!(buf.next_msg(), None);
        assert_eq!(buf.next_release(), SeqNumber(5));
    }

    #[test]
    fn not_ready_none() {
        let mut buf = new_buffer(SeqNumber::new_truncate(5));
        buf.add(DataPacket {
            seq_number: SeqNumber(5),
            message_loc: PacketLocation::FIRST,
            ..basic_pack()
        });
        buf.add(DataPacket {
            seq_number: SeqNumber(7),
            message_loc: PacketLocation::FIRST,
            ..basic_pack()
        });

        assert_eq!(buf.next_msg_ready(), None);
        assert_eq!(buf.next_msg(), None);
        assert_eq!(buf.next_release(), SeqNumber(5));
    }

    #[test]
    fn not_ready_middle() {
        let mut buf = new_buffer(SeqNumber::new_truncate(5));
        buf.add(DataPacket {
            seq_number: SeqNumber(5),
            message_loc: PacketLocation::FIRST,
            ..basic_pack()
        });
        buf.add(DataPacket {
            seq_number: SeqNumber(6),
            message_loc: PacketLocation::empty(),
            ..basic_pack()
        });

        assert_eq!(buf.next_msg_ready(), None);
        assert_eq!(buf.next_msg(), None);
        assert_eq!(buf.next_release(), SeqNumber(5));
    }

    #[test]
    fn ready_single() {
        let mut buf = new_buffer(SeqNumber::new_truncate(5));
        buf.add(DataPacket {
            seq_number: SeqNumber(5),
            message_loc: PacketLocation::FIRST | PacketLocation::LAST,
            payload: From::from(&b"hello"[..]),
            ..basic_pack()
        });
        buf.add(DataPacket {
            seq_number: SeqNumber(6),
            message_loc: PacketLocation::empty(),
            payload: From::from(&b"no"[..]),
            ..basic_pack()
        });

        assert_eq!(buf.next_msg_ready(), Some(1));
        assert_eq!(
            buf.next_msg(),
            Some((buf.time_base.instant_from(0), From::from(&b"hello"[..])))
        );
        assert_eq!(buf.next_release(), SeqNumber(6));
        assert_eq!(buf.buffer.len(), 1);
    }

    #[test]
    fn ready_multi() {
        let mut buf = new_buffer(SeqNumber::new_truncate(5));
        buf.add(DataPacket {
            seq_number: SeqNumber(5),
            message_loc: PacketLocation::FIRST,
            payload: From::from(&b"hello"[..]),
            ..basic_pack()
        });
        buf.add(DataPacket {
            seq_number: SeqNumber(6),
            message_loc: PacketLocation::empty(),
            payload: From::from(&b"yas"[..]),
            ..basic_pack()
        });
        buf.add(DataPacket {
            seq_number: SeqNumber(7),
            message_loc: PacketLocation::LAST,
            payload: From::from(&b"nas"[..]),
            ..basic_pack()
        });

        assert_eq!(buf.next_msg_ready(), Some(3));
        assert_eq!(
            buf.next_msg(),
            Some((
                buf.time_base.instant_from(0),
                From::from(&b"helloyasnas"[..])
            ))
        );
        assert_eq!(buf.next_release(), SeqNumber(8));
        assert_eq!(buf.buffer.len(), 0);
    }
}
