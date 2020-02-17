use crate::packet::ControlTypes::*;

use crate::protocol::receiver::{Receiver, ReceiverAlgorithmAction};
use crate::protocol::sender::{Sender, SenderAlgorithmAction};
use crate::Packet::*;
use crate::{Connection, ConnectionSettings, Packet, SrtCongestCtrl};

use std::cmp::min;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::protocol::handshake::Handshake;
use bytes::Bytes;
use failure::{bail, format_err, Error};
use futures::stream::BoxStream;
use futures::{ready, Future, Sink, Stream, StreamExt};
use log::trace;
use tokio::time::{delay_for, delay_until, Delay};

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementatino to send or receive data.
///
/// The sockets yield and consume `(Instant, Bytes)`, representng the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
pub struct SrtSocket {
    sender: Sender,
    receiver: Receiver,

    stream: BoxStream<'static, Result<(Packet, SocketAddr), Error>>,
    sink: Pin<Box<dyn Sink<(Packet, SocketAddr), Error = Error> + Send>>,

    release_queue: VecDeque<(Instant, Bytes)>,
    send_queue: VecDeque<(Packet, SocketAddr)>,

    closed: bool,

    timer: Delay,
}

/// This spawns two new tasks:
/// 1. Receive packets and send them to either the sender or the receiver through
///    a channel
/// 2. Take outgoing packets and send them on the socket
pub fn create_bidrectional_srt<T>(sock: T, conn: Connection) -> SrtSocket
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Send
        + 'static,
{
    let (sink, stream) = sock.split();

    // Arbitrarilly make the sender responsible for returning handshakes
    SrtSocket {
        sender: Sender::new(conn.settings, conn.handshake, SrtCongestCtrl),
        receiver: Receiver::new(conn.settings, Handshake::Connector),
        stream: stream.boxed(),
        sink: Box::pin(sink),

        release_queue: VecDeque::new(),
        send_queue: VecDeque::new(),

        closed: false,

        timer: delay_for(Duration::from_secs(0)),
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        self.sender.settings()
    }

    fn handle_outgoing(&mut self, cx: &mut Context) -> Result<(), Error> {
        if let Some(p) = self.send_queue.pop_front() {
            if let Poll::Ready(_) = self.sink.as_mut().poll_ready(cx)? {
                trace!("Sending {:?} to underlying socket", p.0);
                self.sink.as_mut().start_send(p)?;
            }
        }
        // rewake this thread if there are still more to send
        if !self.send_queue.is_empty() {
            cx.waker().wake_by_ref();
        }
        let _ = self.sink.as_mut().poll_flush(cx)?;

        Ok(())
    }

    fn tick(&mut self, cx: &mut Context) -> Result<(), Error> {
        self.handle_outgoing(cx)?;

        // handle incomming packet
        while let Poll::Ready(res) = self.stream.as_mut().poll_next(cx) {
            match res {
                Some(Ok((pack, from))) => match &pack {
                    Data(_) => self.receiver.handle_packet(Instant::now(), (pack, from)),
                    Control(cp) => match &cp.control_type {
                        // sender-responsble packets
                        Handshake(_) | Ack { .. } | Nak(_) | DropRequest { .. } => {
                            self.sender
                                .handle_packet((pack, from), Instant::now())
                                .unwrap();
                        }
                        // receiver-respnsible
                        Ack2(_) => self.receiver.handle_packet(Instant::now(), (pack, from)),
                        // both
                        Shutdown | KeepAlive => {
                            self.sender
                                .handle_packet((pack.clone(), from), Instant::now())
                                .unwrap();
                            self.receiver.handle_packet(Instant::now(), (pack, from));
                        }
                        Srt(_) => unimplemented!(),
                    },
                },
                None => bail!("Underlying connection closed!"),
                Some(Err(e)) => return Err(e),
            }
        }

        loop {
            let mut did_sender_timeout = false;
            let mut does_sender_want_close = false;

            // get each's next action
            let sender_timeout = match self.sender.next_action(Instant::now()) {
                SenderAlgorithmAction::WaitUntilAck | SenderAlgorithmAction::WaitForData => None,
                SenderAlgorithmAction::WaitUntil(t) => Some(t),
                SenderAlgorithmAction::Timeout => {
                    did_sender_timeout = true;
                    None
                }
                SenderAlgorithmAction::Close => {
                    trace!("Send returned close");
                    does_sender_want_close = true;
                    None
                }
            };

            while let Some(out) = self.sender.pop_output() {
                self.send_queue.push_back(out);
            }

            let mut did_recvr_timeout = false;
            let recvr_timeout = loop {
                match self.receiver.next_algorithm_action(Instant::now()) {
                    ReceiverAlgorithmAction::TimeBoundedReceive(t2) => {
                        break Some(t2);
                    }
                    ReceiverAlgorithmAction::SendControl(cp, addr) => {
                        self.send_queue.push_back((Control(cp), addr))
                    }
                    ReceiverAlgorithmAction::OutputData(ib) => {
                        self.release_queue.push_back(ib);
                    }
                    ReceiverAlgorithmAction::Timeout => {
                        did_recvr_timeout = true;
                        break None;
                    }
                    ReceiverAlgorithmAction::Close => {
                        trace!("Recv returned close");
                        self.closed = does_sender_want_close;
                        break None;
                    }
                };
            };

            if did_recvr_timeout && did_sender_timeout {
                self.closed = true;
            }

            let timeout = match (sender_timeout, recvr_timeout) {
                (Some(s), Some(r)) => Some(min(s, r)),
                (Some(s), None) => Some(s),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            };

            if self.closed {
                break;
            }

            self.handle_outgoing(cx)?;

            if let Some(to) = timeout {
                self.timer = delay_until(to.into());
                if let Poll::Ready(_) = Pin::new(&mut self.timer).poll(cx) {
                    continue;
                } else {
                    let now = Instant::now();
                    trace!(
                        "{:X} scheduling wakeup at {}{:?} from {}{}",
                        self.sender.settings().local_sockid.0,
                        if to > now { "+" } else { "-" },
                        if to > now { to - now } else { now - to },
                        if sender_timeout.is_some() {
                            "sender "
                        } else {
                            ""
                        },
                        if recvr_timeout.is_some() {
                            "receiver"
                        } else {
                            ""
                        }
                    );

                    break;
                }
            } else {
                trace!(
                    "{:X} not scheduling wakeup!!!",
                    self.sender.settings().local_sockid.0
                );
            }
        }
        Ok(())
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(ib) = self.release_queue.pop_front() {
            trace!("Releasing");
            return Poll::Ready(Some(Ok(ib)));
        }
        if self.closed {
            return Poll::Ready(None);
        }

        self.as_mut().tick(cx)?;

        if let Some(ib) = self.release_queue.pop_front() {
            trace!("Releasing");
            return Poll::Ready(Some(Ok(ib)));
        }

        Poll::Pending
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        if self.closed {
            return Poll::Ready(Err(format_err!("Sink is closed")));
        }
        Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        if self.closed {
            bail!("Sink is closed");
        }
        self.as_mut().sender.handle_data(item);
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.tick(cx)?;
        if self.sender.is_flushed() && self.receiver.is_flushed() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        if !self.closed {
            self.sender.handle_close(Instant::now());
            self.receiver.handle_shutdown();
        }

        ready!(self.as_mut().poll_flush(cx))?;

        self.as_mut().tick(cx)?;

        if !self.send_queue.is_empty() {
            return Poll::Pending;
        }
        Poll::Ready(ready!(self.sink.as_mut().poll_flush(cx)))
    }
}
