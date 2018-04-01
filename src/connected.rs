use std::net::SocketAddr;

use receiver::Receiver;
use sender::Sender;
use socket::SrtSocket;

pub struct Connected {
    socket: SrtSocket,
    remote: SocketAddr,
    remote_sockid: i32,
    init_seq_num: i32,
}

impl Connected {
    pub fn new(
        socket: SrtSocket,
        remote: SocketAddr,
        remote_sockid: i32,
        init_seq_num: i32,
    ) -> Connected {
        Connected {
            socket,
            remote,
            remote_sockid,
            init_seq_num,
        }
    }

    pub fn receiver(self) -> Receiver {
        Receiver::new(
            self.socket,
            self.remote,
            self.remote_sockid,
            self.init_seq_num,
        )
    }

    pub fn sender(self) -> Sender {
        Sender::new(
            self.socket,
            self.remote,
            self.remote_sockid,
            self.init_seq_num,
        )
    }
}
