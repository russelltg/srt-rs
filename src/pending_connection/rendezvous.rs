use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;

use connected::Connected;
use socket::SrtSocket;

pub struct Rendezvous {
	local_public: SocketAddr,
	remote_public: SocketAddr,
	sock: SrtSocket,
}

impl Rendezvous {
	pub fn new(sock: SrtSocket, local_public: SocketAddr, remote_public: SocketAddr) -> Rendezvous {
		Rendezvous {
			sock,		
			local_public,
			remote_public,
		}	
	}

}



impl Future for Rendezvous {
	type Item = Connected;
	type Error = Error;

	fn poll(&mut self) -> Poll<Connected, Error> {
		unimplemented!()
	}
}

