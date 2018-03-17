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
    pub fn new(sock: UdpSocket, timeout: Duration, buffer: T) -> RecvDgramTimeout<T>
    where
        T: AsMut<[u8]>,
    {
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

use tokio::executor::current_thread;
use std::net::ToSocketAddrs;

// tests
#[test]
fn recv_dgram_to_test_none() {
    let addr = "127.0.0.1:8171".to_socket_addrs().unwrap().next().unwrap();

    // try to recieve on the port
    current_thread::run(|_| {
        current_thread::spawn(
            RecvDgramTimeout::new(
                UdpSocket::bind(&addr)
                    .unwrap(),
                Duration::from_secs(1),
                vec![],
            // shouldn't error
            ).map_err(|e| {
                panic!(e);
            })
                // shoudln't get any data
                .map(|(_, vec, sz_addr)| {
                    assert_eq!(vec, vec![]);
                    assert_eq!(sz_addr, None)
                }),
        );

        // send data 2 seconds later
        current_thread::spawn(
            Delay::new(Duration::from_secs(2))
                .and_then(move |_| {
                    UdpSocket::bind(&"127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap())
                        .unwrap()
                        .send_dgram(b"this shouldn't be recvd", &addr)
                })
                .map(|(_, buf)| {
                    assert_eq!(buf, b"this shouldn't be recvd");
                })
                .map_err(|e| {
                    panic!(e);
                }),
        );
    });
}

#[test]
fn recv_dgram_to_test_some() {
    let addr = "127.0.0.1:8172".to_socket_addrs().unwrap().next().unwrap();

    // try to recieve on the port
    current_thread::run(|_| {
        current_thread::spawn(
            RecvDgramTimeout::new(
                UdpSocket::bind(&addr)
                    .unwrap(),
                Duration::from_secs(2),
                b"\0\0\0\0\0\0".to_vec()
            // shouldn't error
            ).map_err(|e| {
                panic!(e);
            })
            // we should get data
            .map(|(_, vec, sz_addr)| {
                if let Some((size, addr)) = sz_addr {
                    assert_eq!(&vec[0..size][0], &b"recvd"[0]);
                } else {
                    panic!("Failed to get data");
                }
            }),
        );

        // send data 1 second later
        current_thread::spawn(
            Delay::new(Duration::from_secs(1))
                .and_then(move |_| {
                    UdpSocket::bind(&"127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap())
                        .unwrap()
                        .send_dgram(b"recvd", &addr)
                })
                .map(|(_, buf)| {
                    assert_eq!(buf, b"recvd");
                })
                .map_err(|e| {
                    panic!(e);
                }),
        );
    });
}
