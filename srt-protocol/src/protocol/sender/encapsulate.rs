use bytes::Bytes;

use crate::{connection::ConnectionSettings, packet::*};

#[derive(Debug)]
pub struct Encapsulate {
    remote_socket_id: SocketId,
    max_packet_size: usize,
    next_message_number: MsgNumber,
    next_sequence_number: SeqNumber,
}

impl Encapsulate {
    const UDP_HEADER_SIZE: u64 = 28; // 20 bytes for IPv4 header, 8 bytes for UDP header
    const HEADER_SIZE: u64 = 16;
    const SRT_DATA_HEADER_SIZE: u64 = Self::UDP_HEADER_SIZE + Self::HEADER_SIZE;

    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_socket_id: settings.remote_sockid,
            max_packet_size: settings.max_packet_size as usize,
            next_sequence_number: settings.init_seq_num,
            next_message_number: MsgNumber::new_truncate(0),
        }
    }

    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets
    pub fn encapsulate<PacketFn: FnMut(DataPacket)>(
        &mut self,
        timestamp: TimeStamp,
        data: Bytes,
        mut handle_packet: PacketFn,
    ) -> (u64, u64) {
        let mut remaining = data;
        let mut location = PacketLocation::FIRST;
        let mut count = 0;
        let mut bytes = 0;
        let message_number = self.next_message_number.increment();
        loop {
            if remaining.len() > self.max_packet_size {
                let this_payload = remaining.slice(0..self.max_packet_size);
                count += 1;
                bytes += Self::SRT_DATA_HEADER_SIZE + this_payload.len() as u64;
                let packet =
                    self.new_data_packet(timestamp, message_number, this_payload, location);
                handle_packet(packet);
                remaining = remaining.slice(self.max_packet_size..remaining.len());
                location = PacketLocation::empty();
            } else {
                count += 1;
                bytes += Self::SRT_DATA_HEADER_SIZE + remaining.len() as u64;
                let packet = self.new_data_packet(
                    timestamp,
                    message_number,
                    remaining,
                    location | PacketLocation::LAST,
                );
                handle_packet(packet);
                return (count, bytes);
            }
        }
    }

    fn new_data_packet(
        &mut self,
        timestamp: TimeStamp,
        message_number: MsgNumber,
        payload: Bytes,
        message_loc: PacketLocation,
    ) -> DataPacket {
        DataPacket {
            dest_sockid: self.remote_socket_id,
            in_order_delivery: false, // TODO: research this
            message_loc,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number,
            seq_number: self.next_sequence_number.increment(),
            timestamp,
            payload,
        }
    }
}
