use crate::packet::ControlTypes::*;

use crate::protocol::connection::{Connection, ConnectionAction};
use crate::protocol::handshake::Handshake;
use crate::protocol::receiver::{Receiver, ReceiverAlgorithmAction};
use crate::protocol::sender::{Sender, SenderAlgorithmAction};
use crate::protocol::TimeBase;
use crate::Packet::*;
use crate::{ConnectionSettings, ControlPacket, Packet, SrtCongestCtrl};

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use failure::Error;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::{future, ready, select};
use log::{debug, error, trace};
use tokio::time::delay_until;

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementatino to send or receive data.
///
/// The sockets yield and consume `(Instant, Bytes)`, representng the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
pub struct SrtSocket {
    // receiver datastructures
    recvr: mpsc::Receiver<(Instant, Bytes)>,

    // sender datastructures
    sender: mpsc::Sender<(Instant, Bytes)>,

    // agnostic
    close: oneshot::Receiver<()>,

    settings: ConnectionSettings,

    _drop_oneshot: oneshot::Sender<()>,
}

/// This spawns two new tasks:
/// 1. Receive packets and send them to either the sender or the receiver through
///    a channel
/// 2. Take outgoing packets and send them on the socket
pub fn create_bidrectional_srt<T>(sock: T, conn: crate::Connection) -> SrtSocket
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Send
        + Unpin
        + 'static,
{
    let (mut release, recvr) = mpsc::channel(128);
    let (sender, new_data) = mpsc::channel(128);
    let (_drop_oneshot, close_oneshot) = oneshot::channel();
    let (close_send, close_recv) = oneshot::channel();
    let conn_copy = conn.clone();

    tokio::spawn(async move {
        let mut close_receiver = close_oneshot.fuse();
        let _close_sender = close_send; // exists for drop
        let mut new_data = new_data.fuse();
        let mut sock = sock.fuse();

        let time_base = TimeBase::new(conn_copy.settings.socket_start_time);
        let mut connection = Connection::new(conn_copy.settings);
        let mut sender = Sender::new(conn_copy.settings, conn_copy.handshake, SrtCongestCtrl);
        let mut receiver = Receiver::new(conn_copy.settings, Handshake::Connector);

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
                        trace!("Recv returned close");
                        return;
                    }
                };
            };
            let connection_timeout = loop {
                match connection.next_action(Instant::now()) {
                    ConnectionAction::ContinueUntil(timeout) => break Some(timeout),
                    ConnectionAction::Close => {
                        if receiver.is_flushed() {
                            return;
                        }
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
                    delay_until(to.into()).await
                } else {
                    trace!(
                        "{:?} not scheduling wakeup!!!",
                        sender.settings().local_sockid
                    );
                    future::pending().await
                }
            };

            select! {
                // one of the entities requested wakeup
                _ = timeout_fut.fuse() => {},
                // new packet received
                res = sock.next() => {
                    match res {
                        Some(Ok((pack, from))) => {
                            connection.on_packet(Instant::now());
                            match &pack {
                                Data(_) => receiver.handle_packet(Instant::now(), (pack, from)),
                                Control(cp) => match &cp.control_type {
                                    // sender-responsble packets
                                    Handshake(_) | Ack { .. } | Nak(_) | DropRequest { .. } => {
                                        sender
                                            .handle_packet((pack, from), Instant::now())
                                            .unwrap();
                                    }
                                    // receiver-respnsible
                                    Ack2(_) => receiver.handle_packet(Instant::now(), (pack, from)),
                                    // both
                                    Shutdown => {
                                        sender
                                            .handle_packet((pack.clone(), from), Instant::now())
                                            .unwrap();
                                        receiver.handle_packet(Instant::now(), (pack, from));
                                    }
                                    // neither--this exists just to keep the connection alive
                                    KeepAlive => {}
                                    Srt(_) => unimplemented!(),
                                },
                            }
                        }
                        None => break,
                        Some(Err(_e)) => break, // TODO: propagate error back
                        a => {},
                    }
                },
                // new packet queued
                res = new_data.next() => {
                    match res {
                        Some(item) => sender.handle_data(item),
                        None => {
                            debug!("Incoming data stream closed");
                            sender.handle_close();
                            // closed = true;
                        }
                    }
                }
                // socket closed
                _ = close_receiver =>  {
                    sender.handle_close()
                }
            }
        }
    });

    SrtSocket {
        recvr,
        sender,
        close: close_recv,
        settings: conn.settings,
        _drop_oneshot,
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        &self.settings
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(Pin::new(&mut self.recvr).poll_next(cx)).map(Ok))
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.sender).poll_ready(cx))?))
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        Ok(self.sender.start_send(item)?)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.sender).poll_flush(cx))?))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.sender).poll_close(cx))?;
        // the sender side of this oneshot is dropped when the task returns, which returns Err here. This means it is closd.
        match Pin::new(&mut self.close).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => unreachable!(),
        }
    }
}
