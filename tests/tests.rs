extern crate futures;
extern crate rand;
extern crate futures_timer;

use std::{
    time::{Duration, Instant},
    collections::BinaryHeap,
    cmp::Ordering,
};

use futures::{
    prelude::*, sync::mpsc
};

use rand::{
    thread_rng,
    distributions::{
        IndependentSample,
        Range,
        Normal,
    }
};

use futures_timer::Delay;

struct LossyConn<T> {
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

impl<T> Stream for LossyConn<T> {
    type Item = T;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<T>, ()> {
        self.receiver.poll()
    }
}

impl<T> Sink for LossyConn<T> {
    type SinkItem = T;
    type SinkError = ();

    fn start_send(&mut self, to_send: T) -> StartSend<T, ()> {
        // should we drop it?
        {
            let between = Range::new(0f64, 1f64);
            let sample = between.ind_sample(&mut thread_rng());

            if sample < self.loss_rate {
                // drop
                return Ok(AsyncSink::Ready);
            }
        }

        // delay
        {
            let center = self.delay_avg.as_secs() as f64 + self.delay_avg.subsec_nanos() as f64 / 1e9;
            let stddev = self.delay_stddev.as_secs() as f64 + self.delay_stddev.subsec_nanos() as f64 / 1e9;

            let between = Normal::new(center, stddev);
            let delay_secs = between.ind_sample(&mut thread_rng());

            let delay = Duration::new(delay_secs.floor() as u64, ((delay_secs % 1.0) * 1e9) as u32);

            self.delay_buffer.push(TTime {
                data: to_send,
                time: Instant::now() + delay,
            })
        }

        // update the timer
        self.delay.reset_at(self.delay_buffer.peek().unwrap().time);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), ()> {
        while let Async::Ready(_) = self.delay.poll().unwrap() {
            let val = match self.delay_buffer.pop() {
                Some(v) => v,
                None => break,
            };
            self.sender.start_send(val.data).unwrap(); // TODO: handle full

            // reset timer
            self.delay.reset_at(self.delay_buffer.peek().unwrap().time);
        }

        Ok(self.sender.poll_complete().unwrap()) // TODO: not this
    }

    fn close(&mut self) -> Poll<(), ()> {
        Ok(self.sender.close().unwrap()) // TODO: here too
    }
}

impl<T> LossyConn<T> {
    fn new(loss_rate: f64, delay_avg: Duration, delay_stddev: Duration) -> (LossyConn<T>, LossyConn<T>) {
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
                delay: Delay::new_at(Instant::now()),
            },
            LossyConn {
                sender: b2a,
                receiver: bfroma,
                loss_rate,
                delay_avg,
                delay_stddev,

                delay_buffer: BinaryHeap::new(),
                delay: Delay::new_at(Instant::now()),
            }
        )
    }
}


