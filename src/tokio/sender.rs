use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use failure::{format_err, Error};
use futures::prelude::*;
use futures::ready;
use log::{debug, info, warn};
use tokio::time::{delay_until, interval, Delay, Interval};

use crate::packet::Packet;
use crate::protocol::handshake::Handshake;
use crate::protocol::sender;
use crate::protocol::sender::SenderAlgorithmAction;
use crate::{CongestCtrl, ConnectionSettings, SrtCongestCtrl, Stats};

pub struct SenderSink<T, CC> {
    sock: T,

    sender: sender::Sender,

    /// The congestion control
    _congest_ctrl: CC,

    /// The send timer
    snd_wait: Option<Delay>,

    /// The interval to report stats with
    stats_interval: Interval,
}

impl<T, CC> SenderSink<T, CC>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
    CC: CongestCtrl + Unpin,
{
    pub fn new(
        sock: T,
        congest_ctrl: CC,
        settings: ConnectionSettings,
        handshake: Handshake,
    ) -> SenderSink<T, CC> {
        info!(
            "Sending started to {:?}, with latency={:?}",
            settings.remote, settings.tsbpd_latency
        );

        SenderSink {
            sock,
            sender: sender::Sender::new(settings, handshake, SrtCongestCtrl),
            _congest_ctrl: congest_ctrl,
            snd_wait: None,
            stats_interval: interval(Duration::from_secs(1)),
        }
    }

    /// Set the interval to get statistics on
    /// Defaults to one second
    pub fn set_stats_interval(&mut self, ivl: Duration) {
        self.stats_interval = interval(ivl);
    }

    pub fn settings(&self) -> &ConnectionSettings {
        &self.sender.settings()
    }

    pub fn remote(&self) -> SocketAddr {
        self.sender.settings().remote
    }

    pub fn stats(&self) -> Stats {
        self.sender.stats(Instant::now())
    }

    fn sock(&mut self) -> Pin<&mut T> {
        Pin::new(&mut self.sock)
    }

    fn send_packets(&mut self, cx: &mut Context) -> Result<(), Error> {
        while let Poll::Ready(()) = self.sock().as_mut().poll_ready(cx)? {
            match self.sender.pop_output() {
                Some(packet) => self.sock().start_send(packet)?,
                None => break,
            }
        }
        let _ = self.sock().poll_flush(cx)?;
        Ok(())
    }

    fn check_sender_flushed(&mut self, cx: &mut Context) -> Result<bool, Error> {
        if let Poll::Ready(_) = self.sock().poll_flush(cx)? {
            // if everything is flushed, return Ok
            if self.sender.is_flushed() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn receive_packets(&mut self, cx: &mut Context) -> Result<(), Error> {
        // do we have any packets to handle?
        while let Poll::Ready(a) = self.sock().poll_next(cx) {
            match a {
                Some(Ok(packet)) => {
                    debug!("Got packet: {:?}", packet);
                    self.sender.handle_packet(packet, Instant::now()).unwrap();
                }
                Some(Err(e)) => warn!("Failed to decode packet: {:?}", e),
                // stream has ended, means shutdown
                None => {
                    return Err(format_err!("Unexpected EOF of underlying stream"));
                }
            }
        }
        Ok(())
    }

    fn check_snd_timer(&mut self, cx: &mut Context) -> bool {
        if let Some(timer) = &mut self.snd_wait {
            match Pin::new(timer).poll(cx) {
                Poll::Pending => return false,
                Poll::Ready(_) => {
                    self.snd_wait = None;
                    self.sender.handle_snd_timer(Instant::now());
                }
            }
        }
        true
    }

    fn process_next_action(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        use SenderAlgorithmAction::*;
        match self.sender.next_action() {
            WaitForData | WaitUntilAck => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            WaitUntil(t) => {
                self.snd_wait = Some(delay_until(t.into()));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Close => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection received shutdown",
            )
            .into())),
        }
    }

    fn poll_sink_flushed(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        if self.check_sender_flushed(cx)? {
            // TODO: this is wrong for KeepAlive
            debug!("Returning ready");
            return Poll::Ready(Ok(()));
        }

        self.receive_packets(cx)?;

        self.send_packets(cx)?;

        if !self.check_snd_timer(cx) {
            return Poll::Pending;
        }

        self.process_next_action(cx)
    }

    fn poll_sink_closed(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.sender.handle_close(Instant::now());

        self.send_packets(cx)?;

        self.sock().poll_close(cx)
    }
}

impl<T, CC> Sink<(Instant, Bytes)> for SenderSink<T, CC>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
    CC: CongestCtrl + Unpin,
{
    type Error = Error;

    fn start_send(mut self: Pin<&mut Self>, item: (Instant, Bytes)) -> Result<(), Error> {
        self.sender.handle_data(item);

        Ok(())
    }

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.get_mut().poll_sink_flushed(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        ready!(self.as_mut().poll_sink_flushed(cx))?;
        self.as_mut().poll_sink_closed(cx)
    }
}

// Stats streaming
impl<T, CC> Stream for SenderSink<T, CC>
where
    T: Stream<Item = Result<(Packet, SocketAddr), Error>>
        + Sink<(Packet, SocketAddr), Error = Error>
        + Unpin,
    CC: CongestCtrl + Unpin,
{
    type Item = Result<Stats, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        ready!(Pin::new(&mut self.stats_interval).poll_next(cx));

        Poll::Ready(Some(Ok(self.stats())))
    }
}
