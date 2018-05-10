extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate futures_timer;
extern crate rand;
extern crate srt;
#[macro_use]
extern crate log;

use bytes::{Bytes, BytesMut};

use std::{
    cmp::Ordering, collections::BinaryHeap, fmt::Debug, io::{Error, ErrorKind}, str, thread,
    time::{Duration, Instant},
};

use futures::{prelude::*, stream::iter_ok, sync::mpsc};

use rand::{
    distributions::{IndependentSample, Normal, Range}, thread_rng,
};

use futures_timer::{Delay, Interval};

use srt::{
    stats_printer::StatsPrinterSender, ConnectionSettings, DefaultSenderCongestionCtrl, Receiver,
    Sender, SeqNumber, SocketID,
};

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

impl<T: Debug> Sink for LossyConn<T> {
    type SinkItem = T;
    type SinkError = ();

    fn start_send(&mut self, to_send: T) -> StartSend<T, ()> {
        // should we drop it?
        {
            let between = Range::new(0f64, 1f64);
            let sample = between.ind_sample(&mut thread_rng());

            if sample < self.loss_rate {
                warn!("Dropping packet: {:?}", to_send);

                // drop
                return Ok(AsyncSink::Ready);
            }
        }

        if self.delay_avg == Duration::from_secs(0) {
            self.sender.start_send(to_send).unwrap();
        } else
        // delay
        {
            let center =
                self.delay_avg.as_secs() as f64 + self.delay_avg.subsec_nanos() as f64 / 1e9;
            let stddev =
                self.delay_stddev.as_secs() as f64 + self.delay_stddev.subsec_nanos() as f64 / 1e9;

            let between = Normal::new(center, stddev);
            let delay_secs = between.ind_sample(&mut thread_rng());

            let delay = Duration::new(delay_secs.floor() as u64, ((delay_secs % 1.0) * 1e9) as u32);

            self.delay_buffer.push(TTime {
                data: to_send,
                time: Instant::now() + delay,
            });

            // update the timer
            self.delay.reset_at(self.delay_buffer.peek().unwrap().time);
        }

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
            if let Some(i) = self.delay_buffer.peek() {
                self.delay.reset_at(i.time);
            }
        }

        Ok(self.sender.poll_complete().unwrap()) // TODO: not this
    }

    fn close(&mut self) -> Poll<(), ()> {
        info!("Closing sink...");

        Ok(self.sender.close().unwrap()) // TODO: here too
    }
}

impl<T> LossyConn<T> {
    fn new(
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
            },
        )
    }
}

struct CounterChecker {
    current: i32,
}

impl Sink for CounterChecker {
    type SinkItem = Bytes;
    type SinkError = Error;

    fn start_send(&mut self, by: Bytes) -> StartSend<Bytes, Error> {
        assert_eq!(
            str::from_utf8(&by[..]).unwrap(),
            self.current.to_string(),
            "Expected data to be {}, was {}",
            self.current,
            str::from_utf8(&by[..]).unwrap()
        );

        if self.current % 100 == 0 {
            info!("{} recognized", self.current);
        }
        self.current += 1;

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), Error> {
        self.poll_complete()
    }
}

#[test]
fn test_with_loss() {
    env_logger::init();

    const INIT_SEQ_NUM: i32 = 812731;
    const ITERS: i32 = 10_000;

    // a stream of ascending stringified integers
    let counting_stream = iter_ok(INIT_SEQ_NUM..(INIT_SEQ_NUM + ITERS))
        .map(|i| BytesMut::from(&i.to_string().bytes().collect::<Vec<_>>()[..]).freeze())
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    let (send, recv) = LossyConn::new(0.01, Duration::from_secs(0), Duration::from_secs(0));

    let sender = StatsPrinterSender::new(
        Sender::new(
            send.map_err(|_| Error::new(ErrorKind::Other, "bad bad"))
                .sink_map_err(|_| Error::new(ErrorKind::Other, "bad bad")),
            DefaultSenderCongestionCtrl::new(),
            ConnectionSettings {
                init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
                socket_start_time: Instant::now(),
                remote_sockid: SocketID(81),
                local_sockid: SocketID(13),
                max_packet_size: 1316,
                max_flow_size: 50_000,
                remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
                tsbpd_latency: None,
            },
        ),
        Duration::from_millis(100),
    );

    let recvr = Receiver::new(
        recv.map_err(|_| Error::new(ErrorKind::Other, "bad bad"))
            .sink_map_err(|_| Error::new(ErrorKind::Other, "bad bad")),
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: None,
        },
    );

    let t1 = thread::spawn(|| {
        sender
            .send_all(counting_stream)
            .map_err(|e: Error| panic!("{:?}", e))
            .wait()
            .unwrap();
    });

    let t2 = thread::spawn(|| {
        CounterChecker {
            current: INIT_SEQ_NUM,
        }.send_all(recvr)
            .map_err(|e| panic!(e))
            .map(move |(c, _)| assert_eq!(c.current, INIT_SEQ_NUM + ITERS))
            .wait()
            .unwrap();
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
