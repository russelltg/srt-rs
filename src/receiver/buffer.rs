use bytes::{Bytes, BytesMut};
use log::debug;
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::packet::PacketLocation;
use crate::{DataPacket, SeqNumber};

static TSBPD_WRAP_PERIOD: u32 = 30_000_000; // 30 seconds (in usec)
static MAX_TIMESTAMP: u32 = std::u32::MAX;  // Full 32 bit (01h11m35s)

pub struct RecvBuffer {
    // stores the incoming packets as they arrive
    // `buffer[0]` will hold sequence number `head`
    buffer: VecDeque<Option<DataPacket>>,

    // The next to be released sequence number
    head: SeqNumber,

    // Whether to check packet time stamp wrap around
    time_wrap_check: bool,

    // base time added to packet timestamp for timestamp wrapping
    time_base: u64,
}

impl RecvBuffer {
    /// Creates a `RecvBuffer`
    ///
    /// * `head` - The sequence number of the next packet
    pub fn new(head: SeqNumber) -> RecvBuffer {
        RecvBuffer {
            buffer: VecDeque::new(),
            head,
            time_wrap_check: false,
            time_base: 0,
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

    fn get_time_base(&mut self, timestamp: u32) -> u64 {
        let mut carryover: u64 = 0;

        if self.time_wrap_check {
            if timestamp < TSBPD_WRAP_PERIOD {
                carryover = MAX_TIMESTAMP as u64 + 1;
            } else if timestamp >= TSBPD_WRAP_PERIOD && timestamp <= (TSBPD_WRAP_PERIOD * 2) {
                self.time_wrap_check = false;
                self.time_base = MAX_TIMESTAMP as u64 + 1;
                debug!("time wrap period ends");
            }
        } else if timestamp > (MAX_TIMESTAMP - TSBPD_WRAP_PERIOD) {
            self.time_wrap_check = true;
            debug!("time wrap period begins");
        }

        self.time_base + carryover
    }

    fn get_pkt_origin_time(&mut self, timestamp: i32) -> u64 {
        self.get_time_base(timestamp as u32) + timestamp as u32 as u64
    }

    fn get_pkt_tsbpd_time(&mut self, timestamp: i32, latency: Duration) -> Duration {
        Duration::from_micros(self.get_pkt_origin_time(timestamp)) + latency
    }

    /// Drops the packets that are deemed to be too late
    /// IE: there is a packet after it that is ready to be released
    ///
    /// Returns the number of packets dropped
    pub fn drop_too_late_packets(&mut self, latency: Duration, start_time: Instant) -> usize {
        let first_non_none_idx = self.buffer.iter().position(Option::is_some);

        let first_non_none_idx = match first_non_none_idx {
            Some(i) => i,
            None => return 0, // even though some of these may be too late, there are none that can be released so they can't them back.
        };

        let first_pack_tsbpd_time = self.get_pkt_tsbpd_time(self.buffer[first_non_none_idx].as_ref().unwrap().timestamp,
                                                            latency);
        // we are too late if that packet is ready
        // give a 2 ms buffer range, be ok with releasing them 2ms late
        if (start_time + first_pack_tsbpd_time + Duration::from_millis(2)) <= Instant::now() {
            debug!(
                "Dropping packets {}..{}, {} ms too late",
                self.head,
                self.head + first_non_none_idx as u32,
                {
                    let dur_too_late = Instant::now() - start_time - first_pack_tsbpd_time;
                    dur_too_late.as_secs() * 1_000
                        + u64::from(dur_too_late.subsec_nanos()) / 1_000_000
                }
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
    ///
    /// Returns `None` if there is no message available, or `Some(i)` if there is a packet available, `i` being the number of packets it spans.
    pub fn next_msg_ready_tsbpd(&mut self, latency: Duration, start_time: Instant) -> Option<usize> {
        let msg_size = self.next_msg_ready()?;

        let pkt_ts = self.buffer.front().unwrap().as_ref().unwrap().timestamp;
        let pkt_tsbpd_time = self.get_pkt_tsbpd_time(pkt_ts, latency);

        if (start_time + pkt_tsbpd_time) <= Instant::now() {
            debug!(
                "Packet was deemed reaady for release, Now={:?}, Ts={:?}, Latency={:?}",
                Instant::now() - start_time,
                Duration::from_micros(self.get_pkt_origin_time(pkt_ts)),
                latency
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
            assert!(first.message_loc.contains(PacketLocation::FIRST));

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

    pub fn next_message_release_time(
        &mut self,
        start_time: Instant,
        latency: Duration,
    ) -> Option<Instant> {
        let _msg_size = self.next_msg_ready()?;

        Some(
            start_time
                + self.get_pkt_tsbpd_time(self.buffer.front().unwrap().as_ref().unwrap().timestamp,
                                          latency)
        )
    }

    /// A convenience function for
    /// `self.next_msg_ready_tsbpd(...).map(|_| self.next_msg().unwrap()`
    pub fn next_msg_tsbpd(
        &mut self,
        latency: Duration,
        start_time: Instant,
    ) -> Option<(u64, Bytes)> {
        self.next_msg_ready_tsbpd(latency, start_time)
            .map(|_| self.next_msg().unwrap())
    }

    /// Check if there is an available message, returning, and its origin timestamp it if found
    pub fn next_msg(&mut self) -> Option<(u64, Bytes)> {
        let count = self.next_msg_ready()?;

        self.head += count as u32;

        let origin_ts = self.get_pkt_origin_time(self.buffer[0].as_ref().unwrap().timestamp);

        // optimize for single packet messages
        if count == 1 {
            return Some((
                origin_ts,
                self.buffer.pop_front().unwrap().unwrap().payload.clone(),
            ));
        }

        // accumulate the rest
        Some((
            origin_ts,
            self.buffer
                .drain(0..count)
                .fold(BytesMut::new(), |mut bytes, pack| {
                    bytes.extend(pack.unwrap().payload);
                    bytes
                })
                .freeze(),
        ))
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
    use super::TSBPD_WRAP_PERIOD;
    use crate::{packet::PacketLocation, DataPacket, MsgNumber, SeqNumber, SocketID};
    use bytes::Bytes;

    fn basic_pack() -> DataPacket {
        DataPacket {
            seq_number: SeqNumber::new(5),
            message_loc: PacketLocation::FIRST,
            in_order_delivery: false,
            message_number: MsgNumber(0),
            timestamp: 0,
            dest_sockid: SocketID(4),
            payload: Bytes::new(),
        }
    }

    #[test]
    fn not_ready_empty() {
        let mut buf = RecvBuffer::new(SeqNumber::new(3));

        assert_eq!(buf.next_msg_ready(), None);
        assert_eq!(buf.next_msg(), None);
        assert_eq!(buf.next_release(), SeqNumber(3));
    }

    #[test]
    fn not_ready_no_more() {
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
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
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
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
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
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
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
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
        assert_eq!(buf.next_msg(), Some((0, From::from(&b"hello"[..]))));
        assert_eq!(buf.next_release(), SeqNumber(6));
        assert_eq!(buf.buffer.len(), 1);
    }

    #[test]
    fn ready_multi() {
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
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
        assert_eq!(buf.next_msg(), Some((0, From::from(&b"helloyasnas"[..]))));
        assert_eq!(buf.next_release(), SeqNumber(8));
        assert_eq!(buf.buffer.len(), 0);
    }

    #[test]
    fn tsbpd_wrap() {
        let mut buf = RecvBuffer::new(SeqNumber::new(5));
        assert_eq!(buf.get_pkt_origin_time(0x7FFFFFFF), 0x7FFFFFFF);
        assert_eq!(buf.get_pkt_origin_time(0x80000000_u32 as i32), 0x80000000);

        assert_eq!(buf.get_pkt_origin_time((0xFFFFFFFF_u32 - TSBPD_WRAP_PERIOD) as i32),
                   0xFFFFFFFF - TSBPD_WRAP_PERIOD as u64);
        assert_eq!(buf.get_pkt_origin_time(0xFFFFFFFE_u32 as i32), 0xFFFFFFFE);
        assert_eq!(buf.get_pkt_origin_time(0xFFFFFFFF_u32 as i32), 0xFFFFFFFF);
        assert_eq!(buf.get_pkt_origin_time(0), 0x100000000);
        assert_eq!(buf.get_pkt_origin_time(1), 0x100000001);
        assert_eq!(buf.get_pkt_origin_time(TSBPD_WRAP_PERIOD as i32),
                   0x100000000 + TSBPD_WRAP_PERIOD as u64);
        assert_eq!(buf.get_pkt_origin_time((TSBPD_WRAP_PERIOD * 2) as i32),
                   0x100000000 + (TSBPD_WRAP_PERIOD * 2) as u64);

        assert_eq!(buf.get_pkt_origin_time((TSBPD_WRAP_PERIOD * 2 + 10) as i32),
                   0x100000000 + (TSBPD_WRAP_PERIOD * 2 + 10) as u64);
    }

}
