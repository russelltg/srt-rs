extern crate srt;

extern crate futures;
extern crate log;
extern crate simple_logger;
extern crate tokio;
extern crate tokio_io;
extern crate url;
extern crate bytes;
#[macro_use]
extern crate clap;

use std::net::{SocketAddr, IpAddr};
use std::io::Error;

use log::LevelFilter;
use tokio::net::UdpSocket;
use tokio::net::UdpFramed;
use tokio_io::codec::BytesCodec;
use tokio::executor::current_thread;
use futures::prelude::*;
use futures::future;
use url::{Url, Host};
use bytes::Bytes;

use srt::socket::SrtSocketBuilder;
use srt::connection::Connection;

fn main() {

	let matches = clap_app!(stransmit_rs => 
		(version: "1.0")
		(author: "Russell Greene")
		(about: "SRT sender and receiver written in rust")
		(@arg VERBOSE: --verbose -v "Log level. More -v's is more logging")
		(@arg FROM: +required "Sets the input url")
		(@arg TO: +required "Sets the output url")
	).get_matches();

	let input_url = match Url::parse(matches.value_of("FROM").unwrap()) {
		Err(e) => panic!("Failed to parse input URL: {}", e),
		Ok(url) => url
	};
	let output_url = match Url::parse(matches.value_of("TO").unwrap()) {
		Err(e) => panic!("Failed to parse output URL: {}", e),
		Ok(url) => url
	};

	// Init logging
    simple_logger::init().unwrap();
	log::set_max_level(match matches.occurrences_of("VERBOSE") {
		0 => LevelFilter::Off,
		1 => LevelFilter::Error,
		2 => LevelFilter::Warn,
		3 => LevelFilter::Info,
		4 => LevelFilter::Debug,
		5 | _ => LevelFilter::Trace,
	});

	let input_host = SocketAddr::new(match input_url.host() {
		Some(Host::Domain(_)) => unimplemented!(),
		Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
		Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
		None => panic!("No host in input url"),
	}, input_url.port().expect("Input URL has no port specified"));

	let from : Box<Future<Item = Box<Stream<Item = Bytes, Error=Error>>, Error=Error>>
			= match input_url.scheme() {
		"udp" => Box::new(future::ok::<Box<Stream<Item=Bytes, Error=Error>>, Error>(
			Box::new(UdpFramed::new(UdpSocket::bind(&input_host).unwrap(), BytesCodec::new()).map(|(b, )| b)))),
		"srt" => Box::new(SrtSocketBuilder::new(input_host).build()),
		s => panic!("unrecignized scheme: {} designated in input url", s),
	};

    current_thread::run(|_| {
    });
}
