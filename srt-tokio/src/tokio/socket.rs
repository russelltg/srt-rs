use crate::packet::ControlTypes::*;

use crate::protocol::connection::{Connection, ConnectionAction};
use crate::protocol::handshake::Handshake;
use crate::protocol::receiver::{Receiver, ReceiverAlgorithmAction};
use crate::protocol::sender::{Sender, SenderAlgorithmAction};
use crate::protocol::TimeBase;
use crate::Packet::*;
use crate::{ConnectionSettings, ControlPacket, Packet};

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::{
    io, mem,
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::{future, ready, select};
use log::{debug, error, info, trace};
use tokio::time::sleep_until;

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementatino to send or receive data.
///
/// The sockets yield and consume `(Instant, Bytes)`, representng the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
#[derive(Debug)]
pub struct SrtSocket {
    // receiver datastructures
    recvr: mpsc::Receiver<(Instant, Bytes)>,

    // sender datastructures
    sender: mpsc::Sender<(Instant, Bytes)>,

    // agnostic
    close: oneshot::Receiver<()>,

    settings: ConnectionSettings,

    // shared state to wake up the
    flush_wakeup: Arc<Mutex<(Option<Waker>, bool)>>,

    _drop_oneshot: oneshot::Sender<()>,
}

#[allow(clippy::large_enum_variant)]
enum Action {
    Nothing,
    CloseSender,
    Send(Option<(Instant, Bytes)>),
    DelegatePacket(Option<(Packet, SocketAddr)>),
}

/// This spawns two new tasks:
/// 1. Receive packets and send them to either the sender or the receiver through
///    a channel
/// 2. Take outgoing packets and send them on the socket
pub fn create_bidrectional_srt<T>(sock: T, conn: crate::Connection) -> SrtSocket
where
    T: Stream<Item = (Packet, SocketAddr)>
        + Sink<(Packet, SocketAddr), Error = io::Error>
        + Send
        + Unpin
        + 'static,
{
    let (mut release, recvr) = mpsc::channel(128);
    let (sender, new_data) = mpsc::channel(128);
    let (_drop_oneshot, close_oneshot) = oneshot::channel();
    let (close_send, close_recv) = oneshot::channel();
    let conn_copy = conn.clone();

    let fw = Arc::new(Mutex::new((None as Option<Waker>, true)));
    let flush_wakeup = fw.clone();

    tokio::spawn(async move {
        let mut close_receiver = close_oneshot.fuse();
        let _close_sender = close_send; // exists for drop
        let mut new_data = new_data.fuse();
        let mut sock = sock.fuse();

        let time_base = TimeBase::new(conn_copy.settings.socket_start_time);
        let mut connection = Connection::new(conn_copy.settings.clone());
        let mut sender = Sender::new(conn_copy.settings.clone(), conn_copy.handshake);
        let mut receiver = Receiver::new(conn_copy.settings, Handshake::Connector);

        let mut flushed = true;
        loop {
            let (sender_timeout, close) = match sender.next_action(Instant::now()) {
                SenderAlgorithmAction::WaitUntilAck | SenderAlgorithmAction::WaitForData => {
                    (None, false)
                }
                SenderAlgorithmAction::WaitUntil(t) => (Some(t), false),
                SenderAlgorithmAction::Close => {
                    trace!("{:?} Send returned close", sender.settings().local_sockid);
                    (None, true)
                }
            };
            while let Some(out) = sender.pop_output() {
                if let Err(e) = sock.send(out).await {
                    error!("Error while seding packet: {:?}", e); // TODO: real error handling
                }
            }

            if close && receiver.is_flushed() {
                trace!(
                    "{:?} Send returned close and receiver flushed",
                    sender.settings().local_sockid
                );
                return;
            } else if close {
                trace!(
                    "{:?} Sender closed, but receiver not flushed",
                    sender.settings().local_sockid
                );
            }

            let recvr_timeout = loop {
                match receiver.next_algorithm_action(Instant::now()) {
                    ReceiverAlgorithmAction::TimeBoundedReceive(t2) => {
                        break Some(t2);
                    }
                    ReceiverAlgorithmAction::SendControl(cp, addr) => {
                        if let Err(e) = sock.send((Packet::Control(cp), addr)).await {
                            error!("Error while sending packet {:?}", e);
                        }
                    }
                    ReceiverAlgorithmAction::OutputData(ib) => {
                        if let Err(e) = release.send(ib).await {
                            error!("Error while releasing packet {:?}", e);
                        }
                    }
                    ReceiverAlgorithmAction::Close => {
                        if sender.is_flushed() {
                            trace!("Recv returned close and sender flushed");
                            return;
                        } else {
                            trace!(
                                "{:?}: receiver closed but not closing as sender is not flushed",
                                sender.settings().local_sockid
                            );
                            break None;
                        }
                    }
                };
            };
            let connection_timeout = loop {
                match connection.next_action(Instant::now()) {
                    ConnectionAction::ContinueUntil(timeout) => break Some(timeout),
                    ConnectionAction::Close => {
                        if receiver.is_flushed() {
                            info!(
                                "{:?} Receiver flush and connection timeout",
                                sender.settings().local_sockid
                            );
                            return;
                        }

                        trace!(
                            "{:?} connection closed but waiting for receiver to flush",
                            sender.settings().local_sockid
                        );

                        break None;
                    } // timeout
                    ConnectionAction::SendKeepAlive => sock
                        .send((
                            Control(ControlPacket {
                                timestamp: time_base.timestamp_from(Instant::now()),
                                dest_sockid: sender.settings().remote_sockid,
                                control_type: KeepAlive,
                            }),
                            sender.settings().remote,
                        ))
                        .await
                        .unwrap(), // todo
                }
            };
            if sender.is_flushed() != flushed {
                // wakeup
                let mut l = fw.lock().unwrap();
                flushed = sender.is_flushed();
                l.1 = sender.is_flushed();
                if sender.is_flushed() {
                    if let Some(waker) = mem::replace(&mut l.0, None) {
                        waker.wake();
                    }
                }
            }

            let timeout = [sender_timeout, recvr_timeout, connection_timeout]
                .iter()
                .filter_map(|&x| x) // Only take Some(x) timeouts
                .min();

            let timeout_fut = async {
                if let Some(to) = timeout {
                    let now = Instant::now();
                    trace!(
                        "{:?} scheduling wakeup at {}{:?} from {}{}",
                        sender.settings().local_sockid,
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
                    sleep_until(to.into()).await
                } else {
                    trace!(
                        "{:?} not scheduling wakeup!!!",
                        sender.settings().local_sockid
                    );
                    future::pending().await
                }
            };

            let action = select! {
                // one of the entities requested wakeup
                _ = timeout_fut.fuse() => Action::Nothing,
                // new packet received
                res = sock.next() =>
                    Action::DelegatePacket(res),
                // new packet queued
                res = new_data.next() => {
                    Action::Send(res)
                }
                // socket closed
                _ = close_receiver =>  {
                    Action::CloseSender
                }
            };
            match action {
                Action::Nothing => {}
                Action::DelegatePacket(res) => {
                    match res {
                        Some((pack, from)) => {
                            connection.on_packet(Instant::now());
                            match &pack {
                                Data(_) => receiver.handle_packet(Instant::now(), (pack, from)),
                                Control(cp) => match &cp.control_type {
                                    // sender-responsble packets
                                    Handshake(_) | Ack { .. } | Nak(_) | DropRequest { .. } => {
                                        sender.handle_packet((pack, from), Instant::now());
                                    }
                                    // receiver-respnsible
                                    Ack2(_) => receiver.handle_packet(Instant::now(), (pack, from)),
                                    // both
                                    Shutdown => {
                                        sender.handle_packet((pack.clone(), from), Instant::now());
                                        receiver.handle_packet(Instant::now(), (pack, from));
                                    }
                                    // neither--this exists just to keep the connection alive
                                    KeepAlive => {}
                                    Srt(s) => {
                                        dbg!(s);
                                        // unimplemented!("{:?}", s);
                                    }
                                },
                            }
                        }
                        None => {
                            info!(
                                "{:?} Exiting because underlying stream ended",
                                sender.settings().local_sockid
                            );
                            break;
                        }
                    }
                }
                Action::Send(res) => match res {
                    Some(item) => {
                        trace!("{:?} queued packet to send", sender.settings().local_sockid);
                        sender.handle_data(item, Instant::now());
                    }
                    None => {
                        debug!("Incoming data stream closed");
                        sender.handle_close();
                    }
                },
                Action::CloseSender => sender.handle_close(),
            }
        }
    });

    SrtSocket {
        recvr,
        sender,
        close: close_recv,
        settings: conn.settings,
        flush_wakeup,
        _drop_oneshot,
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(Pin::new(&mut self.recvr).poll_next(cx)).map(Ok))
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.sender).poll_ready(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?))
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        Ok(self
            .sender
            .start_send(item)
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.sender).poll_flush(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?;

        let mut l = self.flush_wakeup.lock().unwrap();
        if l.1 {
            // already flushed
            Poll::Ready(Ok(()))
        } else {
            // not flushed yet, register wakeup when flushed
            l.0 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.sender).poll_close(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e))?;
        // the sender side of this oneshot is dropped when the task returns, which returns Err here. This means it is closd.
        match Pin::new(&mut self.close).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => unreachable!(),
        }
    }
}
