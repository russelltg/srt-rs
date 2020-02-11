use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::Error;
use futures::{Sink, Stream};
use log::{info, warn};
use tokio::time::{delay_for, Delay};

use crate::protocol::handshake::Handshake;
use crate::protocol::receiver::Receiver;
use crate::protocol::receiver::ReceiverAlgorithmAction;
use crate::{ConnectionSettings, Packet};

pub struct ReceiverStream<T> {
    /// the future to send or recieve packets
    sock: T,

    timer: Delay,

    receiver: Receiver,
}

impl<T> ReceiverStream<T>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    pub fn new(sock: T, settings: ConnectionSettings, handshake: Handshake) -> Self {
        let receiver = Receiver::new(settings, handshake);

        Self {
            sock,
            receiver,
            timer: delay_for(Duration::from_millis(10)),
        }
    }

    fn timer(&mut self) -> Pin<&mut Delay> {
        Pin::new(&mut self.timer)
    }

    fn sock(&mut self) -> Pin<&mut T> {
        Pin::new(&mut self.sock)
    }
}

impl<T> Stream for ReceiverStream<T>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
{
    type Item = Result<(Instant, Bytes), Error>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<(Instant, Bytes), Error>>> {
        let pin = self.get_mut();

        loop {
            use ReceiverAlgorithmAction::*;
            let next_action = pin.receiver.next_algorithm_action(Instant::now());
            if let Poll::Pending = pin.sock().poll_ready(cx) {
                return Poll::Pending;
            }

            match next_action {
                TimeBoundedReceive(t) => {
                    if let Poll::Ready(_) = pin.timer().poll(cx) {
                        pin.timer().reset(t.into());
                    } else {
                        return match pin.sock().poll_next(cx) {
                            Poll::Ready(Some(Ok(p))) => {
                                pin.receiver.handle_packet(Instant::now(), p);
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Ready(Some(Err(e))) => {
                                // TODO: come up with better systematic error story
                                warn!("Error reading packet: {:?}", e);
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Ready(None) => {
                                pin.receiver.handle_shutdown();
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Pending => Poll::Pending,
                        };
                    }
                }
                SendControl(packet, to) => {
                    pin.sock()
                        .start_send((Packet::Control(packet), to))
                        .unwrap();
                }
                OutputData(data) => {
                    return Poll::Ready(Some(Ok(data)));
                }
                Close => {
                    info!("Shutdown received and all packets released, finishing up");
                    return Poll::Ready(None);
                }
            }
        }
    }
}
