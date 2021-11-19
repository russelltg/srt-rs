use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::packet::{FullAckSeqNumber, SeqNumber, TimeSpan};

#[derive(Debug)]
struct AckHistoryEntry {
    /// the highest packet sequence number received that this ACK packet ACKs + 1
    data_seqence_numer: SeqNumber,

    /// the ack sequence number
    ack_sequence_number: FullAckSeqNumber,

    departure_time: Instant,
}

#[derive(Debug)]
pub struct AckHistoryWindow {
    tsbpd_latency: Duration,
    last_ack_dsn: SeqNumber,
    largest_ack2_dsn: SeqNumber,
    buffer: VecDeque<AckHistoryEntry>,
}

impl AckHistoryWindow {
    const LIGHT_ACK_PACKET_INTERVAL: u32 = 64;

    pub fn new(tsbpd_latency: Duration, initial_dsn: SeqNumber) -> Self {
        Self {
            tsbpd_latency,
            last_ack_dsn: initial_dsn,
            largest_ack2_dsn: initial_dsn,
            buffer: VecDeque::with_capacity(20_000 * tsbpd_latency.as_secs_f32() as usize),
        }
    }

    pub fn unacked_packet_count(&self, lrsn: SeqNumber) -> u32 {
        if lrsn < self.largest_ack2_dsn {
            return 0;
        }
        lrsn - self.largest_ack2_dsn
    }

    pub fn is_finished(&self, lrsn: SeqNumber) -> bool {
        self.buffer.is_empty() || lrsn >= self.largest_ack2_dsn
    }

    pub fn reset(&mut self, lrsn: SeqNumber) {
        self.buffer.clear();
        self.largest_ack2_dsn = lrsn;
    }

    pub fn calculate_ack2_rtt(
        &mut self,
        now: Instant,
        ack_seq_num: FullAckSeqNumber,
    ) -> Option<TimeSpan> {
        if ack_seq_num > self.buffer.back()?.ack_sequence_number {
            return None;
        }

        let front = self.buffer.front()?;
        if ack_seq_num < front.ack_sequence_number {
            return None;
        }

        let index = ack_seq_num - front.ack_sequence_number;
        let ack = self.buffer.get(index)?;
        self.largest_ack2_dsn = ack.data_seqence_numer;

        Some(TimeSpan::from_interval(ack.departure_time, now))
    }

    pub fn next_full_ack(
        &mut self,
        now: Instant,
        rtt_mean: TimeSpan,
        next_dsn: SeqNumber,
    ) -> Option<(FullAckSeqNumber, SeqNumber)> {
        // 2) If (a) the ACK number equals to the largest ACK number ever
        //    acknowledged by ACK2
        if self.largest_ack2_dsn == next_dsn {
            return None;
        }

        let is_last_ack_too_recent = |last: &AckHistoryEntry| {
            let interval = TimeSpan::from_interval(last.departure_time, now);
            // make sure this ACK number is greater or equal to one sent previously
            next_dsn < last.data_seqence_numer ||
            // or, (b) it is equal to the ACK number in the
            // last ACK
            next_dsn == last.data_seqence_numer &&
                // and the time interval between these two ACK packets is
                // less than 2 RTTs,
                interval < rtt_mean * 2
        };
        if self.buffer.back().map_or(false, is_last_ack_too_recent) {
            return None;
        }

        // drain expired entries from ACK History Window
        let latency_window = self.tsbpd_latency + Duration::from_millis(10);
        let has_expired = |ack: &AckHistoryEntry| now > ack.departure_time + latency_window;
        while self.buffer.front().map_or(false, has_expired) {
            let _ = self.buffer.pop_front();
        }

        // 3) Assign this ACK a unique increasing full ACK sequence number.
        let next_fasn = self.next_fasn();

        // add it to the ack history
        self.last_ack_dsn = next_dsn;
        self.buffer.push_back(AckHistoryEntry {
            data_seqence_numer: next_dsn,
            ack_sequence_number: next_fasn,
            departure_time: now,
        });

        Some((next_fasn, next_dsn))
    }

    #[must_use]
    pub fn next_light_ack(&mut self, next_dsn: SeqNumber) -> Option<SeqNumber> {
        if next_dsn >= self.last_ack_dsn + Self::LIGHT_ACK_PACKET_INTERVAL {
            self.last_ack_dsn = next_dsn;
            Some(next_dsn)
        } else {
            None
        }
    }

    fn next_fasn(&mut self) -> FullAckSeqNumber {
        self.buffer
            .back()
            .map_or(FullAckSeqNumber::INITIAL, |n| n.ack_sequence_number + 1)
    }
}

#[cfg(test)]
mod ack_history_window {
    use super::*;

    #[test]
    fn light_ack() {
        let tsbpd_latency = Duration::from_secs(1);
        let initial_dsn = SeqNumber(1);

        let mut window = AckHistoryWindow::new(tsbpd_latency, initial_dsn);

        // absent a Full ACK, a Light ACK should be sent every 64 packets
        for i in 0..4 {
            for j in 0..64 {
                let next_light_ack = initial_dsn + j + i * 64;
                assert_eq!(window.next_light_ack(next_light_ack), None);
            }

            let next_light_ack = initial_dsn + 64 + i * 64;
            assert_eq!(window.next_light_ack(next_light_ack), Some(next_light_ack));
        }
    }

    #[test]
    fn full_ack() {
        let start = Instant::now();
        let tsbpd_latency = Duration::from_secs(1);
        let mut next_dsn = SeqNumber(1);

        let mut window = AckHistoryWindow::new(tsbpd_latency, next_dsn);

        let mut now = start;
        let rtt_mean = TimeSpan::from_micros(10_000);

        assert_eq!(
            window.next_full_ack(now, rtt_mean, next_dsn.increment()),
            None
        );

        // loop enough times to ensure that entries expire (test memory leak)
        for n in 0..100_000 {
            let expected_fasn = FullAckSeqNumber::INITIAL + n;
            let expected_dsn = next_dsn.increment();
            assert_eq!(
                window.next_full_ack(now, rtt_mean, expected_dsn),
                Some((expected_fasn, expected_dsn))
            );

            now += Duration::from_millis(1);
            assert_eq!(
                window.calculate_ack2_rtt(now, expected_fasn),
                Some(TimeSpan::from_micros(1_000))
            );
        }

        // the buffer should have an upper bound
        assert_ne!(
            window.buffer.front().unwrap().ack_sequence_number,
            FullAckSeqNumber::INITIAL
        );

        assert_eq!(window.next_light_ack(next_dsn), None);
    }

    #[test]
    fn full_ack_retransmit() {
        let start = Instant::now();
        let tsbpd_latency = Duration::from_secs(1);
        let mut next_dsn = SeqNumber(1);

        let mut window = AckHistoryWindow::new(tsbpd_latency, next_dsn);

        let rtt_mean = TimeSpan::from_micros(10_000);

        // first Full ACK
        let mut now = start;
        let _ = next_dsn.increment();
        window.next_full_ack(now, rtt_mean, next_dsn);

        // only retransmit Full ACK after it's clear that the sender had enough time to respond
        now += Duration::from_micros(10_000);
        assert_eq!(window.next_full_ack(now, rtt_mean, next_dsn), None);
        now += Duration::from_micros(10_000) * 2;
        assert_eq!(
            window.next_full_ack(now, rtt_mean, next_dsn),
            Some((FullAckSeqNumber::INITIAL + 1, next_dsn))
        );

        assert_eq!(window.next_light_ack(next_dsn), None);
    }
}
