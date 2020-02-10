use crate::channel::Channel;
use crate::packet::ControlTypes;
use crate::tokio::receiver::ReceiverStream;
use crate::tokio::sender::SenderSink;
use crate::{Connection, ConnectionSettings, Packet, SrtCongestCtrl};

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use crate::protocol::handshake::Handshake;
use bytes::Bytes;
use failure::Error;
use futures::channel::oneshot;
use futures::{stream, FutureExt, Sink, SinkExt, Stream, StreamExt, TryFutureExt, TryStreamExt};
use log::debug;
use tokio::spawn;

type PackChan = Channel<(Packet, SocketAddr)>;

/// Connected SRT connection, generally created with [`SrtSocketBuilder`](crate::SrtSocketBuilder).
///
/// These are bidirectional sockets, meaning data can be sent in either direction.
/// Use the `Stream + Sink` implementatino to send or receive data.
///
/// The sockets yield and consume `(Bytes, Instant)`, representng the data and the origin instant. This instant
/// defines when the packet will be released on the receiving side, at more or less one latency later.
pub struct SrtSocket {
    // The two tasks started need to be stopped when this struct is dropped
    // because those tasks own the socket, so the file handles won't be released
    // if they aren't stopped.
    //
    // The one forwarding packets to the socket isn't a problem because when
    // sender sides of channels are dropped, their receivers return None, so
    // that task exits correctly. However, the other one needs to wait to
    // receive a packet to realize that it cannot send, which could be any
    // arbitrary time. The fix is to use a oneshot to close that task.
    // This isn't actually used as a sender, it is just used because when the
    // sender gets dropped the receiver gets notified immediately.
    _drop_oneshot: oneshot::Sender<()>,
    sender: SenderSink<PackChan, SrtCongestCtrl>,
    receiver: ReceiverStream<PackChan>,
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
    let (to_s, sender_chan) = Channel::channel(10);
    let (to_r, recvr_chan) = Channel::channel(10);

    let (mut to_s_tx, to_s_rx) = to_s.split();
    let (mut to_r_tx, to_r_rx) = to_r.split();

    let (mut sock_tx, mut sock_rx) = sock.split();

    let (drop_tx, drop_rx) = oneshot::channel();

    // socket -> sender, receiver
    spawn(async move {
        // this needs to be fused here so it actually doesn't get polled after
        // completion
        // the stream doesn't need this as we construct a new futures each time
        let mut drop_fut = drop_rx.fuse();
        while let Some((pack, addr)) = futures::select! {
            recv_e =  sock_rx.try_next().fuse() => recv_e.expect("Underlying stream failed"),
            _ = &mut drop_fut => None,
        } {
            use ControlTypes::*;
            use Packet::*;
            let res = match &pack {
                Data(_) => to_r_tx.send((pack, addr)).await,
                Control(cpk) => match &cpk.control_type {
                    Handshake(_) => to_s_tx.send((pack, addr)).await,
                    KeepAlive => unimplemented!(),
                    Ack { .. } => to_s_tx.send((pack, addr)).await,
                    Nak { .. } => to_s_tx.send((pack, addr)).await,
                    Shutdown => {
                        to_r_tx
                            .send((pack.clone(), addr))
                            .and_then(|_| to_s_tx.send((pack, addr)))
                            .await
                    }
                    Ack2(_) => to_r_tx.send((pack, addr)).await,
                    DropRequest { .. } => to_s_tx.send((pack, addr)).await,
                    Srt(_) => unimplemented!(),
                },
            };
            if res.is_err() {
                break;
            }
        }
        debug!("Closing recv task!");
    });
    // sender, receiver -> socket
    spawn(async move {
        let mut combined = stream::select(to_s_rx, to_r_rx);
        while let Some(pa) = combined.try_next().await.expect("underlying stream failed") {
            sock_tx
                .send(pa)
                .await
                .expect("Failed to send to underlying socket");
        }
        debug!("Closing tx task!");
    });

    // Arbitrarilly make the sender responsible for returning handshakes
    SrtSocket {
        _drop_oneshot: drop_tx,
        sender: SenderSink::new(sender_chan, SrtCongestCtrl, conn.settings, conn.handshake),
        receiver: ReceiverStream::new(recvr_chan, conn.settings, Handshake::Connector),
    }
}

impl SrtSocket {
    pub fn settings(&self) -> &ConnectionSettings {
        self.sender.settings()
    }
}

impl Stream for SrtSocket {
    type Item = Result<(Instant, Bytes), Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Sink<(Instant, Bytes)> for SrtSocket {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender).poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Self::Error> {
        Pin::new(&mut self.sender).start_send(item)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender).poll_close(cx)
    }
}
