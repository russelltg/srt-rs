use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;

use connected::Connected;
use socket::SrtSocket;

pub struct Connect {
    remote: SocketAddr,
    sock: SrtSocket,
}

impl Connect {
    pub fn new(sock: SrtSocket, remote: SocketAddr) -> Connect {
        Connect { sock, remote }
    }
}

impl Future for Connect {
    type Item = Connected;
    type Error = Error;

    fn poll(&mut self) -> Poll<Connected, Error> {
        unimplemented!()
    }
}
