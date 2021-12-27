use bytes::Bytes;

use crate::{connection::ConnectionSettings, options::PacketSize, packet::*};

#[derive(Debug)]
pub struct Encapsulation {
    remote_socket_id: SocketId,
    max_packet_size: PacketSize,
    next_message_number: MsgNumber,
    next_sequence_number: SeqNumber,
}

impl Encapsulation {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self {
            remote_socket_id: settings.remote_sockid,
            max_packet_size: settings.max_packet_size,
            next_sequence_number: settings.init_seq_num,
            next_message_number: MsgNumber::new_truncate(0),
        }
    }

    /// In the case of a message longer than the packet size,
    /// It will be split into multiple packets
    pub fn encapsulate(
        &mut self,
        timestamp: TimeStamp,
        data: Bytes,
    ) -> impl Iterator<Item = DataPacket> + '_ {
        MessageEncapsulationIterator {
            timestamp,
            message_number: self.next_message_number.increment(),
            remaining: data,
            packet_location: PacketLocation::FIRST,
            remote_socket_id: self.remote_socket_id,
            max_packet_size: self.max_packet_size,
            next_sequence_number: &mut self.next_sequence_number,
        }
    }
}

struct MessageEncapsulationIterator<'a> {
    next_sequence_number: &'a mut SeqNumber,
    remote_socket_id: SocketId,
    max_packet_size: PacketSize,
    remaining: Bytes,
    packet_location: PacketLocation,
    message_number: MsgNumber,
    timestamp: TimeStamp,
}

impl<'a> Iterator for MessageEncapsulationIterator<'a> {
    type Item = DataPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.packet_location.contains(PacketLocation::LAST) {
            return None;
        }

        let (payload, message_loc) = if self.remaining.len() > self.max_packet_size.into() {
            let payload = self.remaining.split_to(self.max_packet_size.into());
            let packet_location = self.packet_location;
            self.packet_location = PacketLocation::MIDDLE;
            (payload, packet_location)
        } else {
            let payload = self.remaining.split_to(self.remaining.len());
            self.packet_location |= PacketLocation::LAST;
            (payload, self.packet_location)
        };

        Some(DataPacket {
            dest_sockid: self.remote_socket_id,
            in_order_delivery: false, // TODO: research this
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: self.message_number,
            seq_number: self.next_sequence_number.increment(),
            timestamp: self.timestamp,
            message_loc,
            payload,
        })
    }
}

#[cfg(test)]
mod encapsulation {
    use super::*;

    fn new_encapsulation() -> Encapsulation {
        Encapsulation {
            remote_socket_id: SocketId(2),
            max_packet_size: PacketSize(1024),
            next_message_number: MsgNumber(1),
            next_sequence_number: SeqNumber(0),
        }
    }

    #[test]
    fn empty_message() {
        let data = Bytes::from_static(&[0u8; 0]);

        let mut encapsulation = new_encapsulation();

        assert_eq!(encapsulation.encapsulate(TimeStamp::MAX, data).count(), 1);
    }

    #[test]
    fn large_message() {
        let data = Bytes::from_static(&[0u8; 10240]);

        let mut encapsulation = new_encapsulation();

        assert_eq!(encapsulation.encapsulate(TimeStamp::MAX, data).count(), 10);
    }
}
