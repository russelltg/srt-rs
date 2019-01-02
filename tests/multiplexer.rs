use std::thread;
use std::time::Instant;

use srt::{ConnInitMethod, MultiplexerServer, SrtSocketBuilder};

use futures::stream::{iter_ok, Stream};
use futures::Future;

use failure::Error;

use bytes::Bytes;

#[test]
fn multiplexer() {
    let _ = env_logger::try_init();

    let multiplexer_thread = thread::Builder::new()
        .name("Overall multiplexer".to_string())
        .spawn(|| {
            let mut server =
                Some(MultiplexerServer::bind(&"127.0.0.1:2000".parse().unwrap()).unwrap());

            let mut handles = vec![];

            for i in 0..10 {
                let (conn, new_server) = server
                    .take()
                    .unwrap()
                    .into_future()
                    .map_err(|(e, _)| e)
                    .wait()
                    .unwrap();

                let conn = conn.unwrap();

                let stream =
                    iter_ok::<_, Error>(Some((Instant::now(), Bytes::from("asdf"))).into_iter());

                let send_to = stream
                    .forward(conn.sender())
                    .map_err(|e: Error| panic!("{:?}", e))
                    .map(|_| {});

                handles.push(
                    thread::Builder::new()
                        .name(format!("sender {}", i))
                        .spawn(move || send_to.wait().unwrap())
                        .unwrap(),
                );

                server = Some(new_server);
            }

            // server needs to be continued to be polled even here
            thread::Builder::new()
                .name("multiplexer-final".to_string())
                .spawn(move || {
                    server
                        .take()
                        .unwrap()
                        .into_future()
                        .map_err(|(e, _)| e)
                        .wait()
                        .unwrap();
                    unreachable!(); // this should never resolve
                })
                .unwrap();

            for i in handles {
                i.join().unwrap();
            }
        })
        .unwrap();

    // connect 10 clients to it
    let threads = (0..10)
        .map(|i| {
            thread::Builder::new()
                .name(format!("Receiveer {}", i))
                .spawn(|| {
                    let conn_init = SrtSocketBuilder::new(ConnInitMethod::Connect(
                        "127.0.0.1:2000".parse().unwrap(),
                    ))
                    .build()
                    .unwrap();

                    let client = conn_init
                        .and_then(|conn| {
                            let recvr = conn.receiver();

                            recvr.into_future().map_err(|(e, _)| e)
                        })
                        .map(|(pack, _)| {
                            let (_, pack) = pack.unwrap();
                            println!("Got packet!");
                            assert_eq!(&pack, "asdf");
                        })
                        .map_err(|e| panic!(e));

                    client.wait().unwrap();
                })
                .unwrap()
        })
        .collect::<Vec<_>>();

    multiplexer_thread.join().unwrap();
    for i in threads {
        i.join().unwrap();
    }
}
