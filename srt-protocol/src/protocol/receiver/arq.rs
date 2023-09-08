use std::{
    ops::Range,
    time::{Duration, Instant},
};

use array_init::from_iter;
use arraydeque::{behavior::Wrapping, ArrayDeque};
use bytes::Bytes;

use crate::{
    options::PacketCount,
    packet::*,
    protocol::{
        receiver::{
            buffer::{MessageError, ReceiveBuffer},
            history::AckHistoryWindow,
            time::ClockAdjustment,
            DataPacketAction, DataPacketError,
        },
        time::Rtt,
    },
};

#[derive(Debug)]
pub struct ArrivalSpeed {
    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// PKT History Window: A circular array that records the arrival time
    /// of each data packet.
    ///
    /// Instead of arrival time we store packet arrival intervals and data size
    /// in the PKT History Window.
    packet_history_window: ArrayDeque<(TimeSpan, u64), 16, Wrapping>,
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
        // 4) Calculate the packet arrival speed according to the following
        // algorithm:

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
        let filtered: ArrayDeque<_, 16> = window
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
    packet_pair_window: ArrayDeque<TimeSpan, 16, Wrapping>,
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

        // 5) Calculate the estimated link capacity according to the following algorithm:
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
pub struct AutomaticRepeatRequestAlgorithm {
    link_capacity_estimate: LinkCapacityEstimate,
    arrival_speed: ArrivalSpeed,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// Receiver's Loss List: It is a list of tuples whose values include:
    /// the sequence numbers of detected lost data packets, the latest
    /// feedback time of each tuple, and a parameter k that is the number
    /// of times each one has been fed back in NAK. Values are stored in
    /// the increasing order of packet sequence numbers.
    receive_buffer: ReceiveBuffer,

    /// https://tools.ietf.org/html/draft-gg-udt-03#page-12
    /// ACK History Window: A circular array of each sent ACK and the time
    /// it is sent out. The most recent value will overwrite the oldest
    /// one if no more free space in the array.
    ack_history_window: AckHistoryWindow,

    rtt: Rtt,
}

impl AutomaticRepeatRequestAlgorithm {
    pub fn new(
        socket_start_time: Instant,
        tsbpd_latency: Duration,
        too_late_packet_drop: bool,
        init_seq_num: SeqNumber,
        buffer_size_packets: PacketCount,
    ) -> Self {
        Self {
            link_capacity_estimate: LinkCapacityEstimate::new(),
            arrival_speed: ArrivalSpeed::new(),
            receive_buffer: ReceiveBuffer::new(
                socket_start_time,
                tsbpd_latency,
                too_late_packet_drop,
                init_seq_num,
                buffer_size_packets,
            ),
            ack_history_window: AckHistoryWindow::new(tsbpd_latency, init_seq_num),
            rtt: Rtt::default(),
        }
    }

    pub fn is_flushed(&self) -> bool {
        self.receive_buffer.is_empty()
            && self
                .ack_history_window
                .is_finished(self.receive_buffer.next_ack_dsn())
    }

    pub fn unacked_packet_count(&self) -> u32 {
        self.ack_history_window
            .unacked_packet_count(self.receive_buffer.next_ack_dsn())
    }

    pub fn next_message_release_time(&self) -> Option<Instant> {
        self.receive_buffer.next_message_release_time()
    }

    pub fn clear(&mut self) {
        self.receive_buffer.clear();
        self.ack_history_window
            .reset(self.receive_buffer.next_ack_dsn());
    }

    pub fn synchronize_clock(
        &mut self,
        now: Instant,
        now_ts: TimeStamp,
    ) -> Option<ClockAdjustment> {
        self.receive_buffer.synchronize_clock(now, now_ts)
    }

    pub fn on_full_ack_event(&mut self, now: Instant) -> Option<Acknowledgement> {
        // NOTE: if a Full ACK is sent when the receive buffer is full, the Sender will stall
        if self.receive_buffer.buffer_available() == 0 {
            return None;
        }

        let (fasn, dsn) = self.ack_history_window.next_full_ack(
            now,
            self.rtt.mean(),
            self.receive_buffer.next_ack_dsn(),
        )?;

        let arrival_speed = self.arrival_speed.calculate();

        let statistics = AckStatistics {
            rtt: self.rtt,
            buffer_available: self.receive_buffer.buffer_available() as u32,
            packet_receive_rate: arrival_speed.map(|(packets, _)| packets),
            estimated_link_capacity: arrival_speed.map(|(_, bytes)| bytes),
            data_receive_rate: self.link_capacity_estimate.calculate(),
        };

        Some(Acknowledgement::Full(dsn, statistics, fasn))
    }

    pub fn on_nak_event(&mut self, now: Instant) -> Option<CompressedLossList> {
        self.receive_buffer.prepare_loss_list(now, self.rtt.mean())
    }

    pub fn handle_data_packet(
        &mut self,
        now: Instant,
        packet: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        let seq_number = packet.seq_number;
        let size = packet.payload.len();
        let action = match self.receive_buffer.push_packet(now, packet)? {
            DataPacketAction::Received { lrsn, recovered } => {
                if !recovered {
                    self.update_link_estimates(now, seq_number, size);
                }
                self.next_light_ack(lrsn, recovered)
            }
            action => action,
        };
        Ok(action)
    }

    fn update_link_estimates(&mut self, now: Instant, seq_number: SeqNumber, size: usize) {
        // 4) If the sequence number of the current data packet is 16n + 1,
        //     where n is an integer, record the time interval between this
        self.link_capacity_estimate
            .record_data_packet(now, seq_number);

        // 5) Record the packet arrival time in PKT History Window.
        self.arrival_speed.record_data_packet(now, size);
    }

    fn next_light_ack(&mut self, lrsn: SeqNumber, recovered: bool) -> DataPacketAction {
        use DataPacketAction::*;
        self.ack_history_window
            .next_light_ack(lrsn)
            .map(|light_ack| ReceivedWithLightAck {
                light_ack,
                recovered,
            })
            .unwrap_or(Received { lrsn, recovered })
    }

    pub fn handle_ack2_packet(
        &mut self,
        now: Instant,
        ack_seq_num: FullAckSeqNumber,
    ) -> Option<&Rtt> {
        if let Some(rtt) = self.ack_history_window.calculate_ack2_rtt(now, ack_seq_num) {
            // 3) Calculate new rtt according to the ACK2 arrival time and the ACK
            //    , and update the RTT value as: RTT = (RTT * 7 +
            //    rtt) / 8
            // 4) Update RTTVar by: RTTVar = (RTTVar * 3 + abs(RTT - rtt)) / 4.
            self.rtt.update(rtt);
            Some(&self.rtt)
        } else {
            None
        }
    }

    pub fn handle_drop_request(&mut self, _now: Instant, range: Range<SeqNumber>) -> usize {
        self.receive_buffer.drop_packets(range)
    }

    pub fn pop_next_message(
        &mut self,
        now: Instant,
    ) -> Result<Option<(Instant, Bytes)>, MessageError> {
        self.receive_buffer.pop_next_message(now)
    }

    pub fn rx_acknowledged_time(&self) -> Duration {
        self.receive_buffer.rx_acknowledged_time()
    }
}

#[cfg(test)]
mod automatic_repeat_request_algorithm {
    use assert_matches::assert_matches;
    use bytes::Bytes;

    use DataPacketAction::*;

    use super::*;

    fn basic_pack() -> DataPacket {
        DataPacket {
            seq_number: SeqNumber(0),
            message_loc: PacketLocation::FIRST,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: MsgNumber(0),
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(4),
            payload: Bytes::from(vec![0; 10]),
        }
    }

    #[test]
    fn handle_data_packet_with_loss() {
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(
            start,
            Duration::from_secs(2),
            true,
            init_seq_num,
            PacketCount(8192),
        );

        assert_eq!(arq.on_full_ack_event(start), None);
        assert_eq!(arq.on_nak_event(start), None);
        assert_eq!(
            arq.pop_next_message(start + Duration::from_secs(10)),
            Ok(None)
        );
        assert!(arq.is_flushed());

        assert_eq!(
            arq.handle_data_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert!(!arq.is_flushed());
        assert_eq!(
            arq.handle_data_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 3,
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 1..init_seq_num + 3).into()
            ))
        );

        assert!(!arq.is_flushed());

        assert_eq!(
            arq.pop_next_message(start + Duration::from_secs(10)),
            Err(MessageError {
                too_late_packets: SeqNumber(5)..SeqNumber(8),
                delay: TimeSpan::from_millis(8_000)
            })
        );
    }

    #[test]
    fn ack_event() {
        let start = Instant::now();
        let init_seq_num = SeqNumber(1);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(
            start,
            Duration::from_secs(2),
            true,
            init_seq_num,
            PacketCount(8192),
        );

        assert_eq!(
            arq.handle_data_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            arq.handle_data_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(
            arq.on_full_ack_event(start),
            Some(Acknowledgement::Full(
                init_seq_num + 2,
                AckStatistics {
                    rtt: Rtt::default(),
                    buffer_available: 8190,
                    packet_receive_rate: None,
                    estimated_link_capacity: None,
                    data_receive_rate: None
                },
                FullAckSeqNumber::INITIAL
            ))
        );

        assert_eq!(
            arq.handle_data_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 3,
                recovered: false
            })
        );
        assert!(!arq.is_flushed());
    }

    #[test]
    fn ack2_packet() {
        let start = Instant::now();
        let init_seq_num = SeqNumber(1);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(
            start,
            Duration::from_secs(2),
            true,
            init_seq_num,
            PacketCount(8192),
        );

        let _ = arq.handle_data_packet(
            start,
            DataPacket {
                seq_number: init_seq_num,
                ..basic_pack()
            },
        );
        let _ = arq.handle_data_packet(
            start,
            DataPacket {
                seq_number: init_seq_num + 1,
                ..basic_pack()
            },
        );
        let _ = arq.on_full_ack_event(start);
        let _ = arq.handle_data_packet(
            start,
            DataPacket {
                seq_number: init_seq_num + 2,
                ..basic_pack()
            },
        );
        assert_eq!(arq.rtt.mean(), Rtt::default().mean());
        assert!(!arq.is_flushed());

        let rtt =
            arq.handle_ack2_packet(start + Duration::from_millis(1), FullAckSeqNumber::INITIAL);
        assert_ne!(rtt.map(|r| r.mean()), Some(Rtt::default().mean()));
        assert!(!arq.is_flushed());
    }

    #[test]
    fn is_flushed() {
        let start = Instant::now();
        let init_seq_num = SeqNumber(1);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(
            start,
            Duration::from_secs(1),
            true,
            init_seq_num,
            PacketCount(8192),
        );

        let _ = arq.handle_data_packet(
            start,
            DataPacket {
                seq_number: init_seq_num,
                message_loc: PacketLocation::ONLY,
                ..basic_pack()
            },
        );

        assert_eq!(
            arq.on_full_ack_event(start),
            Some(Acknowledgement::Full(
                init_seq_num + 1,
                AckStatistics {
                    rtt: Rtt::default(),
                    buffer_available: 8191,
                    packet_receive_rate: None,
                    estimated_link_capacity: None,
                    data_receive_rate: None
                },
                FullAckSeqNumber::INITIAL
            ))
        );

        let now = start + Duration::from_millis(10);
        assert_matches!(
            arq.handle_ack2_packet(now, FullAckSeqNumber::INITIAL),
            Some(_)
        );
        assert_eq!(arq.pop_next_message(now), Ok(None));

        let now = start + Duration::from_secs(10);
        assert_eq!(
            arq.pop_next_message(now),
            Ok(Some((start, Bytes::from(vec![0u8; 10]))))
        );
        assert!(arq.is_flushed());
    }

    #[test]
    fn nak_event() {
        let start = Instant::now();
        let tsbpd_latency = Duration::from_secs(2);
        let init_seq_num = SeqNumber(5);
        let mut arq = AutomaticRepeatRequestAlgorithm::new(
            start,
            tsbpd_latency,
            true,
            init_seq_num,
            PacketCount(8192),
        );

        let now = start;
        let _ = arq.handle_data_packet(
            now,
            DataPacket {
                seq_number: init_seq_num,
                ..basic_pack()
            },
        );
        let _ = arq.handle_data_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 4,
                ..basic_pack()
            },
        );
        assert_eq!(arq.on_nak_event(now), None);

        let now = start + arq.rtt.mean();
        assert_eq!(arq.on_nak_event(now), None);

        let now = start + arq.rtt.mean() * 4;
        assert_eq!(
            arq.on_nak_event(now),
            Some((init_seq_num + 1..init_seq_num + 4).into())
        );

        let now = start + arq.rtt.mean() * 5;
        assert_eq!(arq.on_nak_event(now), None);

        let now = start + arq.rtt.mean() * 8;
        assert_eq!(
            arq.on_nak_event(now),
            Some((init_seq_num + 1..init_seq_num + 4).into())
        );

        let now = start + tsbpd_latency + Duration::from_millis(10);
        // should drop late messages, not pop them
        assert_eq!(
            arq.pop_next_message(now),
            Err(MessageError {
                too_late_packets: SeqNumber(5)..SeqNumber(9),
                delay: TimeSpan::from_millis(10)
            })
        );
        assert_eq!(arq.on_nak_event(now), None);
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
