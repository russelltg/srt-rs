extern crate srt;

extern crate bytes;
extern crate futures;
extern crate log;
extern crate simple_logger;
extern crate tokio;
extern crate tokio_io;
extern crate url;
#[macro_use]
extern crate clap;

use std::net::{IpAddr, SocketAddr};
use std::io::Error;

use log::LevelFilter;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;
use tokio_io::codec::BytesCodec;
use tokio::executor::current_thread;
use futures::prelude::*;
use futures::future;
use url::{Host, Url};
use bytes::Bytes;

use srt::socket::SrtSocketBuilder;

fn main() {
    let matches = clap_app!(stransmit_rs =>
		(version: "1.0")
		(author: "Russell Greene")
		(about: "SRT sender and receiver written in rust")
		(@arg verbose: -v --verbose ... "Log level. More -v's is more logging")
		(@arg FROM: +required "Sets the input url")
		(@arg TO: +required "Sets the output url")
	).get_matches();

    let input_url = match Url::parse(matches.value_of("FROM").unwrap()) {
        Err(e) => panic!("Failed to parse input URL: {}", e),
        Ok(url) => url,
    };
    let output_url = match Url::parse(matches.value_of("TO").unwrap()) {
        Err(e) => panic!("Failed to parse output URL: {}", e),
        Ok(url) => url,
    };

    // Init logging
    simple_logger::init().unwrap();
    log::set_max_level(match matches.occurrences_of("verbose") {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 | _ => LevelFilter::Trace,
    });

    let input_host = SocketAddr::new(
        match input_url.host() {
            Some(Host::Domain(d)) => d.parse().expect("Unable to parse url in input"),
            Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
            None => panic!("No host in input url"),
        },
        input_url.port().expect("Input URL has no port specified"),
    );

    // Resolve the receiver side
    // this will be a future that resolves to a stream of bytes
    // (all boxed to allow for different protocols)
    let from: Box<Future<Item = Box<Stream<Item = Bytes, Error = Error>>, Error = Error>> =
        match input_url.scheme() {
            "udp" => Box::new(
                future::ok::<Box<Stream<Item = Bytes, Error = Error>>, Error>(Box::new(
                    UdpFramed::new(UdpSocket::bind(&input_host).unwrap(), BytesCodec::new())
                        .map(|(b, _)| b.freeze()),
                )),
            ),
            // TODO: flags
            "srt" => {
                Box::new(SrtSocketBuilder::new(input_host).build().unwrap().map(
                    |c| -> Box<Stream<Item = Bytes, Error = Error>> { Box::new(c.receiver()) },
                ))
            }
            s => panic!("unrecognized scheme: {} designated in input url", s),
        };

    let output_host = SocketAddr::new(
        match output_url.host() {
            Some(Host::Domain(d)) => d.parse().expect("Failed to parse output ip address"),
            Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
            None => panic!("No host in input url"),
        },
        output_url.port().expect("Input URL has no port specified"),
    );

    // Resolve the sender side
    // similar to the receiver side, except a sink instead of a stream
    let to: Box<Future<Item = Box<Sink<SinkItem = Bytes, SinkError = Error>>, Error = Error>> =
        match output_url.scheme() {
            "udp" => Box::new(future::ok::<
                Box<Sink<SinkItem = Bytes, SinkError = Error>>,
                Error,
            >(Box::new(
                UdpFramed::new(
                    UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap(),
                    BytesCodec::new(),
                ).with(move |b| future::ok((b, output_host))),
            ))),
            "srt" => Box::new(SrtSocketBuilder::new(output_host).build().unwrap().map(
                |c| -> Box<Sink<SinkItem = Bytes, SinkError = Error>> { Box::new(c.sender()) },
            )),
            s => panic!("unrecognized scheme: {} designated in output url", s),
        };

    current_thread::run(|_| {
        current_thread::spawn(
            from.join(to)
                .and_then(|(from, to)| from.forward(to))
                .map_err(|e| eprintln!("Error encountered: {:?}", e))
                .map(|_| ()),
        );
    });
}
