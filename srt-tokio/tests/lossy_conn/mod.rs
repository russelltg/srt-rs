use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt::Debug;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

use futures::channel::mpsc;
use futures::{ready, stream::Fuse, Future, Sink, Stream, StreamExt};

use tokio::time::{self, delay_for, Delay};

use anyhow::Result;

use log::{debug, info, trace, warn};

use rand::distributions::Distribution;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_distr::Normal;
use srt_protocol::PacketParseError;

pub struct LossyConn<T> {
    sender: mpsc::Sender<(T, SocketAddr)>,
    receiver: Fuse<mpsc::Receiver<(T, SocketAddr)>>,

    loss_rate: f64,
    delay_avg: Duration,
    delay_stddev: Duration,

    remote_addr: SocketAddr,
    local_addr: SocketAddr,

    delay_buffer: BinaryHeap<TTime<(T, SocketAddr)>>,
    delay: Delay,

    generator: StdRng,
}

struct TTime<T> {
    data: T,
    time: Instant,
}

impl<T> Ord for TTime<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time.cmp(&self.time)
    }
}

impl<T> PartialOrd for TTime<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> PartialEq for TTime<T> {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl<T> Eq for TTime<T> {}

// Have the queue on the Stream impl so that way flushing doesn't act strangely.
impl<T: Unpin + Debug> Stream for LossyConn<T> {
    type Item = Result<(T, SocketAddr), PacketParseError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        if let Some(ttime) = pin.delay_buffer.peek() {
            if ttime.time <= Instant::now() {
                let val = pin.delay_buffer.pop().unwrap();

                // reset timer
                if let Some(i) = pin.delay_buffer.peek() {
                    pin.delay.reset(time::Instant::from_std(i.time));
                }

                trace!(
                    "Forwarding packet {:?}, queue.len={}",
                    val.data,
                    pin.delay_buffer.len()
                );
                return Poll::Ready(Some(Ok(val.data)));
            }
        }
        // poll this after, just in case we reset it
        let _pret = Pin::new(&mut pin.delay).poll(cx);

        loop {
            let to_send = match ready!(Pin::new(&mut pin.receiver).poll_next(cx)) {
                None => {
                    trace!("Connection ended");
                    // just always return Pening--that's what UDP sockets do, they don't "end"
                    return Poll::Pending;
                }
                Some(to_send) => to_send,
            };

            if pin.generator.gen::<f64>() < pin.loss_rate {
                debug!("Dropping packet: {:?}", to_send);

                // drop
                continue;
            }

            if pin.delay_avg == Duration::from_secs(0) {
                // return it
                return Poll::Ready(Some(Ok(to_send)));
            }
            // delay
            let center = pin.delay_avg.as_secs_f64();
            let stddev = pin.delay_stddev.as_secs_f64();
            let between = Normal::new(center, stddev).unwrap();
            let delay_secs = f64::abs(between.sample(&mut pin.generator));

            let delay = Duration::from_secs_f64(delay_secs);

            pin.delay_buffer.push(TTime {
                data: to_send,
                time: Instant::now() + delay,
            });

            // update the timer
            pin.delay.reset(time::Instant::from_std(
                pin.delay_buffer.peek().unwrap().time,
            ));
            let _ = Pin::new(&mut pin.delay).poll(cx);
        }
    }
}

impl<T: Sync + Send + Unpin + 'static> Sink<(T, SocketAddr)> for LossyConn<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let _ = ready!(self.sender.poll_ready(cx));
        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        (val, addr): (T, SocketAddr),
    ) -> Result<(), Self::Error> {
        if addr != self.remote_addr {
            warn!(
                "Discarding packet not directed at remote. Remote is {}, was sent to {}",
                self.remote_addr, addr
            );
            return Ok(());
        }
        // just discard it, like a real UDP connection
        let local = self.local_addr;
        let _ = self.sender.start_send((val, local));
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.sender).poll_flush(cx)).unwrap();
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.sender).poll_close(cx)).unwrap();
        Poll::Ready(Ok(()))
    }
}

impl<T> LossyConn<T> {
    pub fn with_seed(
        loss_rate: f64,
        delay_avg: Duration,
        delay_stddev: Duration,
        local_a: impl ToSocketAddrs,
        local_b: impl ToSocketAddrs,
        seed: u64,
    ) -> (Self, Self) {
        let (a2b, bfroma) = mpsc::channel(10000);
        let (b2a, afromb) = mpsc::channel(10000);

        let mut r1 = StdRng::seed_from_u64(seed);
        let r2 = StdRng::seed_from_u64(r1.gen());

        let local_a = local_a.to_socket_addrs().unwrap().next().unwrap();
        let local_b = local_b.to_socket_addrs().unwrap().next().unwrap();

        info!("Lossy seed is {}", seed);
        (
            LossyConn {
                sender: a2b,
                receiver: afromb.fuse(),
                loss_rate,
                delay_avg,
                delay_stddev,

                local_addr: local_a,
                remote_addr: local_b,

                delay_buffer: BinaryHeap::new(),
                delay: delay_for(Duration::from_secs(0)),

                generator: r1,
            },
            LossyConn {
                sender: b2a,
                receiver: bfroma.fuse(),
                loss_rate,
                delay_avg,
                delay_stddev,

                local_addr: local_b,
                remote_addr: local_a,

                delay_buffer: BinaryHeap::new(),
                delay: delay_for(Duration::from_secs(0)),

                generator: r2,
            },
        )
    }
    pub fn channel(
        loss_rate: f64,
        delay_avg: Duration,
        delay_stddev: Duration,
        local_a: impl ToSocketAddrs,
        local_b: impl ToSocketAddrs,
    ) -> (Self, Self) {
        let s = match std::env::var("LOSSY_CONN_SEED") {
            Ok(s) => {
                info!("Using seed from env");
                s.parse().unwrap()
            }
            Err(_) => rand::random(),
        };
        Self::with_seed(loss_rate, delay_avg, delay_stddev, local_a, local_b, s)
    }
}
