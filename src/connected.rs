use std::io::Error;
use std::net::SocketAddr;
use std::time::Instant;

use futures::prelude::*;

use DefaultCongestionControl;
use Packet;
use receiver::Receiver;
use sender::Sender;

pub struct Connected<T> {
    socket: T,
    remote: SocketAddr,
    remote_sockid: i32,
    local_sockid: i32,
    socket_start_time: Instant,
    init_seq_num: i32,
}

impl<T> Connected<T>
where
    T: Stream<Item = (Packet, SocketAddr), Error = Error>
        + Sink<SinkItem = (Packet, SocketAddr), SinkError = Error>,
{
    pub fn new(
        socket: T,
        remote: SocketAddr,
        remote_sockid: i32,
        local_sockid: i32,
        socket_start_time: Instant,
        init_seq_num: i32,
    ) -> Connected<T> {
        Connected {
            socket,
            remote,
            remote_sockid,
            local_sockid,
            socket_start_time,
            init_seq_num,
        }
    }

    pub fn receiver(self) -> Receiver<T> {
        Receiver::new(
            self.socket,
            self.remote,
            self.remote_sockid,
            self.init_seq_num,
            self.local_sockid,
            self.socket_start_time,
        )
    }

    pub fn sender(self) -> Sender<T, DefaultCongestionControl> {
        Sender::new(
            self.socket,
            DefaultCongestionControl::new(),
            self.local_sockid,
            self.socket_start_time,
            self.remote,
            self.remote_sockid,
            self.init_seq_num,
        )
    }
}
