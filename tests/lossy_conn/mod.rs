use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt::Debug;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use failure::{format_err, Error};

use futures::channel::mpsc;
use futures::{ready, Future, Sink, Stream};

use tokio::time::{self, delay_for, Delay};

use log::{debug, info};

use rand;
use rand::distributions::Distribution;
use rand_distr::Normal;

pub struct LossyConn<T> {
    sender: mpsc::Sender<T>,
    receiver: mpsc::Receiver<T>,

    loss_rate: f64,
    delay_avg: Duration,
    delay_stddev: Duration,

    delay_buffer: BinaryHeap<TTime<T>>,
    delay: Delay,
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

impl<T: Unpin> Stream for LossyConn<T> {
    type Item = Result<T, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(Pin::new(&mut self.receiver).poll_next(cx)).map(Ok))
    }
}

impl<T: Debug + Sync + Send + Unpin + 'static> Sink<T> for LossyConn<T> {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, to_send: T) -> Result<(), Error> {
        let pin = self.get_mut();
        // should we drop it?
        {
            if rand::random::<f64>() < pin.loss_rate {
                debug!("Dropping packet: {:?}", to_send);

                // drop
                return Ok(());
            }
        }

        if pin.delay_avg == Duration::from_secs(0) {
            pin.sender.start_send(to_send)?;
        } else
        // delay
        {
            let center = pin.delay_avg.as_secs_f64();
            let stddev = pin.delay_stddev.as_secs_f64();
            let between = Normal::new(center, stddev).unwrap();
            let delay_secs = f64::abs(between.sample(&mut rand::thread_rng()));

            let delay = Duration::from_secs_f64(delay_secs);

            pin.delay_buffer.push(TTime {
                data: to_send,
                time: Instant::now() + delay,
            });

            // update the timer
            pin.delay.reset(time::Instant::from_std(
                pin.delay_buffer.peek().unwrap().time,
            ));
        }

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();

        while let Poll::Ready(_) = Pin::new(&mut pin.delay).poll(cx) {
            let val = match pin.delay_buffer.pop() {
                Some(v) => v,
                None => break,
            };
            if let Err(err) = pin.sender.try_send(val.data) {
                if err.is_disconnected() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(format_err!("{}", err)));
            }

            // reset timer
            if let Some(i) = pin.delay_buffer.peek() {
                pin.delay.reset(time::Instant::from_std(i.time));
            }
        }

        Poll::Ready(Ok(ready!(Pin::new(&mut pin.sender).poll_flush(cx))?))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        info!("Closing sink...");

        Poll::Ready(Ok(ready!(Pin::new(&mut self.sender).poll_close(cx))?))
    }
}

impl<T> LossyConn<T> {
    pub fn channel(
        loss_rate: f64,
        delay_avg: Duration,
        delay_stddev: Duration,
    ) -> (LossyConn<T>, LossyConn<T>) {
        let (a2b, bfroma) = mpsc::channel(10000);
        let (b2a, afromb) = mpsc::channel(10000);

        (
            LossyConn {
                sender: a2b,
                receiver: afromb,
                loss_rate,
                delay_avg,
                delay_stddev,

                delay_buffer: BinaryHeap::new(),
                delay: delay_for(Duration::from_secs(0)),
            },
            LossyConn {
                sender: b2a,
                receiver: bfroma,
                loss_rate,
                delay_avg,
                delay_stddev,

                delay_buffer: BinaryHeap::new(),
                delay: delay_for(Duration::from_secs(0)),
            },
        )
    }
}
