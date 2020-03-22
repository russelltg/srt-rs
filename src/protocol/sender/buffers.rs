use std::collections::VecDeque;
use std::time::Instant;

use bytes::Bytes;

use crate::packet::PacketLocation;
use crate::protocol::time::{TimeBase, TimeStamp};
use crate::{ConnectionSettings, DataPacket, MsgNumber, SeqNumber, SocketID};

pub struct TransmitBuffer {
    remote_socket_id: SocketID,
    max_packet_size: usize,
    time_base: TimeBase,

    /// The list of packets to transmit
    buffer: VecDeque<DataPacket>,

    /// The sequence number for the next data packet
    pub next_sequence_number: SeqNumber,

    /// The message number for the next message
    pub next_message_number: MsgNumber,
}

impl TransmitBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_socket_id: settings.remote_sockid,
            max_packet_size: settings.max_packet_size as usize,
            time_base: TimeBase::new(settings.socket_start_time),
            buffer: Default::default(),
            next_sequence_number: settings.init_seq_num,
            next_message_number: MsgNumber::new_truncate(0),
        }
    }

    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets
    pub fn push_message(&mut self, data: (Instant, Bytes)) -> usize {
        let (time, mut payload) = data;
        let mut location = PacketLocation::FIRST;
        let mut packet_count = 0;
        let message_number = self.get_new_message_number();
        loop {
            if payload.len() > self.max_packet_size as usize {
                let this_payload = payload.slice(0..self.max_packet_size as usize);
                self.begin_transmit(time, message_number, this_payload, location);
                payload = payload.slice(self.max_packet_size as usize..payload.len());
                location = PacketLocation::empty();
                packet_count += 1;
            } else {
                self.begin_transmit(
                    time,
                    message_number,
                    payload,
                    location | PacketLocation::LAST,
                );
                return packet_count + 1;
            }
        }
    }

    pub fn pop_front(&mut self) -> Option<DataPacket> {
        self.buffer.pop_front()
    }

    pub fn front(&self) -> Option<&DataPacket> {
        self.buffer.front()
    }

    pub fn latest_seqence_number(&self) -> SeqNumber {
        self.next_sequence_number - 1
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn timestamp_from(&self, at: Instant) -> TimeStamp {
        self.time_base.timestamp_from(at)
    }

    fn begin_transmit(
        &mut self,
        time: Instant,
        message_num: MsgNumber,
        payload: Bytes,
        location: PacketLocation,
    ) {
        let packet = DataPacket {
            dest_sockid: self.remote_socket_id,
            in_order_delivery: false, // TODO: research this
            message_loc: location,
            // if this marks the beginning of the next message, get a new message number, else don't
            message_number: message_num,
            seq_number: self.get_new_sequence_number(),
            timestamp: self.timestamp_from(time),
            payload,
        };

        self.buffer.push_back(packet)
    }

    /// Gets the next available message number
    fn get_new_message_number(&mut self) -> MsgNumber {
        self.next_message_number += 1;
        self.next_message_number - 1
    }

    /// Gets the next avilabe packet sequence number
    fn get_new_sequence_number(&mut self) -> SeqNumber {
        // this does looping for us
        self.next_sequence_number += 1;
        self.next_sequence_number - 1
    }
}

pub struct SendBuffer {
    /// The buffer to store packets for retransmision, sorted chronologically
    buffer: VecDeque<DataPacket>,

    /// The first sequence number in buffer, so seq number i would be found at
    /// buffer[i - first_seq]
    first_seq: SeqNumber,
}

impl SendBuffer {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            buffer: Default::default(),
            first_seq: settings.init_seq_num,
        }
    }

    pub fn release_acknowledged_packets(&mut self, acknowledged: SeqNumber) {
        while acknowledged > self.first_seq {
            self.buffer.pop_front();
            self.first_seq += 1;
        }
    }

    pub fn get<'a, I: Iterator<Item = SeqNumber> + 'a>(
        &'a self,
        numbers: I,
    ) -> impl Iterator<Item = Result<&'a DataPacket, SeqNumber>> + 'a {
        numbers.map(
            move |number| match self.buffer.get((number - self.first_seq) as usize) {
                Some(p) => Ok(p),
                None => Err(number),
            },
        )
    }

    pub fn push_back(&mut self, data: DataPacket) {
        self.buffer.push_back(data);
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

pub struct LossList {
    pub list: VecDeque<DataPacket>,
}

impl LossList {
    pub fn new(_settings: &ConnectionSettings) -> Self {
        Self {
            list: VecDeque::new(),
        }
    }

    pub fn push_back(&mut self, packet: DataPacket) {
        self.list.push_back(packet);
    }

    pub fn pop_front(&mut self) -> Option<DataPacket> {
        self.list.pop_front()
    }

    pub fn remove_acknowledged_packets(&mut self, acknowledged: SeqNumber) -> u32 {
        let mut retransmited_packets = 0;
        while let Some(x) = self.list.front() {
            if acknowledged > x.seq_number {
                let _ = self.pop_front();
                // this means a packet was lost then retransmitted
                retransmited_packets += 1;
            } else {
                break;
            }
        }
        retransmited_packets
    }

    pub fn back(&self) -> Option<&DataPacket> {
        self.list.back()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}
