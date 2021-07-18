use crate::packet::{DataEncryption, PacketLocation};
use crate::protocol::{TimeBase, TimeStamp};
use crate::{ConnectionSettings, DataPacket, MsgNumber, SeqNumber, SocketId};
use bytes::Bytes;
use std::time::Instant;

#[derive(Debug)]
pub struct Encapsulate {
    remote_socket_id: SocketId,
    max_packet_size: usize,
    time_base: TimeBase,
    next_message_number: MsgNumber,
    pub next_sequence_number: SeqNumber,
}

impl Encapsulate {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_socket_id: settings.remote_sockid,
            max_packet_size: settings.max_packet_size as usize,
            time_base: TimeBase::new(settings.socket_start_time),
            next_sequence_number: settings.init_seq_num,
            next_message_number: MsgNumber::new_truncate(0),
        }
    }

    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets
    pub fn encapsulate<PacketFn: FnMut(DataPacket)>(
        &mut self,
        data: (Instant, Bytes),
        mut handle_packet: PacketFn,
    ) -> u64 {
        let (time, mut payload) = data;
        let mut location = PacketLocation::FIRST;
        let mut packet_count = 0;
        let message_number = self.next_message_number.increment();
        loop {
            if payload.len() > self.max_packet_size as usize {
                let this_payload = payload.slice(0..self.max_packet_size as usize);
                let packet =
                    self.new_data_packet(time, message_number, this_payload, location, false);
                handle_packet(packet);
                payload = payload.slice(self.max_packet_size as usize..payload.len());
                location = PacketLocation::empty();
                packet_count += 1;
            } else {
                let packet = self.new_data_packet(
                    time,
                    message_number,
                    payload,
                    location | PacketLocation::LAST,
                    false,
                );
                handle_packet(packet);
                return packet_count + 1;
            }
        }
    }

    fn new_data_packet(
        &mut self,
        time: Instant,
        message_num: MsgNumber,
        payload: Bytes,
        location: PacketLocation,
        retransmitted: bool,
    ) -> DataPacket {
        DataPacket {
            dest_sockid: self.remote_socket_id,
            in_order_delivery: false, // TODO: research this
            message_loc: location,
            encryption: DataEncryption::None,
            retransmitted,
            // if this marks the beginning of the next message, get a new message number, else don't
            message_number: message_num,
            seq_number: self.next_sequence_number.increment(),
            timestamp: self.timestamp_from(time),
            payload,
        }
    }

    pub fn timestamp_from(&self, at: Instant) -> TimeStamp {
        self.time_base.timestamp_from(at)
    }
}
