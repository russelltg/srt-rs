use std::time::Duration;
use std::io::Error;
use std::net::SocketAddr;

use futures::prelude::*;
use tokio::net::UdpSocket;

use futures_timer::Delay;

pub struct RecvDgramTimeout<T> {
    state: Option<RecvDgramTimeoutInner<T>>,
}

pub struct RecvDgramTimeoutInner<T> {
    sock: UdpSocket,
    timeout: Delay,
    buffer: T,
}

impl<T> RecvDgramTimeout<T> {
    pub fn new(sock: UdpSocket, timeout: Duration, buffer: T) -> RecvDgramTimeout<T> {
        RecvDgramTimeout {
            state: Some(RecvDgramTimeoutInner {
                sock,
                timeout: Delay::new(timeout),
                buffer,
            }),
        }
    }
    
}

impl<T> Future for RecvDgramTimeout<T>
where
    T: AsMut<[u8]>,
{
    type Item = (UdpSocket, T, Option<(usize, SocketAddr)>);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Error> {
        // have we timed out?
        let timed_out = {
            let ref mut inner = self.state.as_mut().expect("Polled after completion");

            if let Async::Ready(_) = inner.timeout.poll()? {
                true
            } else {
                false
            }
        };
        if timed_out {
            let inner = self.state.take().unwrap();
            return Ok(Async::Ready((inner.sock, inner.buffer, None)));
        }

        let (n, addr) = {
            let ref mut inner = self.state.as_mut().unwrap();
            
            try_nb!(inner.sock.recv_from(inner.buffer.as_mut()))
        };

        let inner = self.state.take().unwrap();
        Ok(Async::Ready((inner.sock, inner.buffer, Some((n, addr)))))
    }
}
