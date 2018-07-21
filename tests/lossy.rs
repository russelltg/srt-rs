extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate futures_timer;
extern crate rand;
extern crate srt;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

use {
    bytes::Bytes, failure::Error, futures::{prelude::*, stream::iter_ok, sync::mpsc},
    futures_timer::{Delay, Interval}, rand::distributions::{Distribution, Normal},
    srt::{
        ConnectionSettings, HandshakeResponsibility, Receiver, Sender, SeqNumber, SocketID,
        SrtCongestCtrl,
    },
    std::{
        cmp::Ordering, collections::BinaryHeap, fmt::Debug, str, thread, time::{Duration, Instant},
    },
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
            if rand::random::<f64>() < self.loss_rate {
                debug!("Dropping packet: {:?}", to_send);

                // drop
                return Ok(AsyncSink::Ready);
            }
        }

        if self.delay_avg == Duration::from_secs(0) {
            debug!("Sending packet: {:?}", to_send);
            self.sender.start_send(to_send).unwrap();
        } else
        // delay
        {
            let center =
                self.delay_avg.as_secs() as f64 + self.delay_avg.subsec_nanos() as f64 / 1e9;
            let stddev =
                self.delay_stddev.as_secs() as f64 + self.delay_stddev.subsec_nanos() as f64 / 1e9;

            let between = Normal::new(center, stddev);
            let delay_secs = between.sample(&mut rand::thread_rng());

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
            debug!("Sending packet: {:?}", val.data);
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

#[test]
fn test_with_loss() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 812731;
    const ITERS: u32 = 10_000;

    // a stream of ascending stringified integers
    let counting_stream = iter_ok(INIT_SEQ_NUM..(INIT_SEQ_NUM + ITERS))
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_micros(100)))
        .map(|(b, _)| b);

    let (send, recv) = LossyConn::new(0.05, Duration::from_secs(0), Duration::from_secs(0));

    let sender = Sender::new(
        send.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        SrtCongestCtrl,
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(81),
            local_sockid: SocketID(13),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
            tsbpd_latency: None,
            responsibility: HandshakeResponsibility::Request,
        },
    );

    let recvr = Receiver::new(
        recv.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: None,
            responsibility: HandshakeResponsibility::Respond,
        },
    );

    let t1 = thread::spawn(|| {
        sender
            .send_all(counting_stream.map(|b| (Instant::now(), b)))
            .map_err(|e: Error| panic!("{:?}", e))
            .wait()
            .unwrap();
    });

    let t2 = thread::spawn(|| {
        let mut next_data = INIT_SEQ_NUM;

        for payload in recvr.wait() {
            let (_, payload) = payload.unwrap();

            assert_eq!(next_data.to_string(), str::from_utf8(&payload[..]).unwrap());

            next_data += 1;
        }

        assert_eq!(next_data, INIT_SEQ_NUM + ITERS);
    });

    t1.join().unwrap();
    t2.join().unwrap();
}

#[test]
// This test is currently broken--TSBPD timing hasn't been implemented correctly yet
#[ignore]
fn tsbpd() {
    let _ = env_logger::try_init();

    const INIT_SEQ_NUM: u32 = 12314;

    // a stream of ascending stringified integers
    // 1 ms between packets
    let counting_stream = iter_ok(INIT_SEQ_NUM..)
        .map(|i| Bytes::from(i.to_string()))
        .zip(Interval::new(Duration::from_millis(1)))
        .map(|(b, _)| b);

    // 1% packet loss, 1 sec latency with 0.2 s variance
    let (send, recv) = LossyConn::new(0.01, Duration::from_secs(1), Duration::from_millis(200));

    let sender = Sender::new(
        send.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        SrtCongestCtrl,
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(81),
            local_sockid: SocketID(13),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(), // doesn't matter, it's getting discarded
            tsbpd_latency: Some(Duration::from_secs(5)), // five seconds TSBPD, should be plenty for no loss
            responsibility: HandshakeResponsibility::Request,
        },
    );

    let recvr = Receiver::new(
        recv.map_err(|_| format_err!(""))
            .sink_map_err(|_| format_err!("")),
        ConnectionSettings {
            init_seq_num: SeqNumber::new(INIT_SEQ_NUM),
            socket_start_time: Instant::now(),
            remote_sockid: SocketID(13),
            local_sockid: SocketID(81),
            max_packet_size: 1316,
            max_flow_size: 50_000,
            remote: "0.0.0.0:0".parse().unwrap(),
            tsbpd_latency: Some(Duration::from_secs(5)),
            responsibility: HandshakeResponsibility::Respond,
        },
    );

    let t1 = thread::spawn(|| {
        sender
            .send_all(counting_stream.map(|b| (Instant::now(), b)))
            .map_err(|e: Error| panic!("{:?}", e))
            .wait()
            .unwrap();
    });

    let t2 = thread::spawn(|| {
        let mut iter = recvr.wait();

        let mut next_num = INIT_SEQ_NUM;

        // wait 5ish seconds for some good warmup
        {
            let start = Instant::now();

            while start.elapsed() < Duration::from_secs(5) {
                iter.next().unwrap().unwrap();
                next_num += 1;
            }
        }

        let mut last_time = Instant::now();

        for by in iter {
            let (_, by) = by.unwrap();
            assert_eq!(
                str::from_utf8(&by[..]).unwrap(),
                next_num.to_string(),
                "Expected data to be {}, was {}",
                next_num,
                str::from_utf8(&by[..]).unwrap()
            );

            next_num += 1;

            // we want between 0.9 ms and 2 ms latency
            let ms = (last_time.elapsed().subsec_nanos() as f64
                + last_time.elapsed().as_secs() as f64 * 1e9) / 1e6;
            assert!(
                last_time.elapsed() > Duration::from_micros(900)
                    && last_time.elapsed() < Duration::from_millis(2),
                "time elapsed={}ms, expected between 0.9ms and 2ms",
                ms
            );

            last_time = Instant::now();
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
