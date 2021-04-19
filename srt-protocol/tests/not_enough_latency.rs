// use bytes::Bytes;
// use futures::{stream::iter, SinkExt, StreamExt};
// use log::{debug, info};
// use std::str;
// /// A test testing if a connection is setup with not enough latency, ie rtt > 3ish*latency
// use std::time::{Duration, Instant};

// use srt_tokio::{ConnInitMethod, SrtSocketBuilder};

// mod lossy_conn;
// use crate::lossy_conn::LossyConn;

// #[tokio::test]
// async fn not_enough_latency() {
//     let _ = pretty_env_logger::try_init();

//     const INIT_SEQ_NUM: u32 = 12314;
//     const PACKETS: u32 = 1_000;

//     // a stream of ascending stringified integers
//     // 1 ms between packets
//     let counting_stream = tokio_stream::StreamExt::throttle(
//         iter(INIT_SEQ_NUM..INIT_SEQ_NUM + PACKETS).map(|i| Bytes::from(i.to_string())),
//         Duration::from_millis(1),
//     )
//     .boxed();

//     // 4% packet loss, 4 sec latency with 0.2 s variance
//     let (send, recv) = LossyConn::channel(
//         0.04,
//         Duration::from_secs(4),
//         Duration::from_millis(200),
//         "127.0.0.1:1000",
//         "127.0.0.1:1",
//     );

//     let sender = SrtSocketBuilder::new(ConnInitMethod::Listen)
//         .local_port(1000)
//         .connect_with_sock(send);
//     let recvr = SrtSocketBuilder::new_connect("127.0.0.1:1000").connect_with_sock(recv);

//     tokio::spawn(async move {
//         let mut sender = sender.await.unwrap();
//         let mut stream = counting_stream.map(|b| Ok((Instant::now(), b)));
//         sender.send_all(&mut stream).await.unwrap();
//         sender.close().await.unwrap();

//         info!("Sender exiting");
//     });

//     tokio::spawn(async move {
//         let mut recvr = recvr.await.unwrap();
//         let mut last_seq_num = INIT_SEQ_NUM - 1;

//         let mut total = 0;

//         while let Some(by) = recvr.next().await {
//             let (ts, by) = by.unwrap();

//             total += 1;

//             // they don't have to be sequential, but they should be increasing
//             let this_seq_num = str::from_utf8(&by[..]).unwrap().parse().unwrap();
//             assert!(
//                 this_seq_num > last_seq_num,
//                 "Sequence numbers aren't increasing"
//             );
//             if this_seq_num - last_seq_num > 1 {
//                 debug!("{} messages dropped", this_seq_num - last_seq_num - 1)
//             }
//             last_seq_num = this_seq_num;

//             // make sure the timings are still decent
//             let diff_ms = ts.elapsed().as_millis();
//             assert!(
//                 diff_ms > 4900 && diff_ms < 6000,
//                 "Time difference {}ms not within 4.7 sec and 6 sec",
//                 diff_ms,
//             );
//         }

//         // make sure we got 3/4 of the packets
//         assert!(
//             total > PACKETS * 3 / 4,
//             "total={}, expected={}",
//             total,
//             PACKETS * 3 / 4
//         );

//         info!("Reciever exiting");
//     });
// }
