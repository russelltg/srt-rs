extern crate srt;

extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate log;
extern crate tokio_io;
extern crate tokio_udp;
extern crate url;
#[macro_use]
extern crate clap;

use std::{io::Error, net::{IpAddr, Ipv4Addr, SocketAddr}};

use bytes::Bytes;
use futures::{future, prelude::*};
use tokio_io::codec::BytesCodec;
use tokio_udp::{UdpFramed, UdpSocket};
use url::{Host, Url};

use srt::{ConnInitMethod, SrtSocketBuilder};

fn main() {
    env_logger::init();

    let addr_any: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

    let matches = clap_app!(stransmit_rs =>
		(version: "1.0")
		(author: "Russell Greene")
		(about: "SRT sender and receiver written in rust")
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

    // Resolve the receiver side
    // this will be a future that resolves to a stream of bytes
    // (all boxed to allow for different protocols)
    let from: Box<Future<Item = Box<Stream<Item = Bytes, Error = Error>>, Error = Error>> = {
        let (input_local_port, input_addr) = {
            let port = input_url.port().expect("Intput URL has no port specified");

            match input_url.host() {
                None => (port, None),
                Some(Host::Domain(d)) if d == "" => (port, None),
                Some(Host::Domain(d)) => (
                    0,
                    Some(SocketAddr::new(
                        d.parse().expect("Failed to parse intput ip address"),
                        port,
                    )),
                ),
                Some(Host::Ipv4(v4)) => (0, Some(SocketAddr::new(IpAddr::V4(v4), port))),
                Some(Host::Ipv6(v6)) => (0, Some(SocketAddr::new(IpAddr::V6(v6), port))),
            }
        };

        let input_local_addr = SocketAddr::new(addr_any, input_local_port);

        if input_url.scheme() == "udp" && input_local_port == 0 {
            panic!("Must not designate a ip to send to receive UDP. Example: udp://:1234, not udp://127.0.0.1:1234");
        }

        match input_url.scheme() {
            "udp" => Box::new(
                future::ok::<Box<Stream<Item = Bytes, Error = Error>>, Error>(Box::new(
                    UdpFramed::new(
                        UdpSocket::bind(&input_local_addr).unwrap(),
                        BytesCodec::new(),
                    ).map(|(b, _)| b.freeze()),
                )),
            ),
            // TODO: flags
            "srt" => Box::new(
                SrtSocketBuilder::new(
                    input_local_addr,
                    input_addr.map_or(ConnInitMethod::Listen, ConnInitMethod::Connect),
                ).build()
                    .unwrap()
                    .map(|c| -> Box<Stream<Item = Bytes, Error = Error>> {
                        Box::new(c.receiver())
                    }),
            ),
            s => panic!("unrecognized scheme: {} designated in input url", s),
        }
    };

    // Resolve the sender side
    // similar to the receiver side, except a sink instead of a stream
    let to: Box<Future<Item = Box<Sink<SinkItem = Bytes, SinkError = Error>>, Error = Error>> = {
        let (output_local_port, output_addr) = {
            let port = output_url.port().expect("Output URL has no port specified");

            match output_url.host() {
                None => (port, None),
                Some(Host::Domain(d)) if d == "" => (port, None),
                Some(Host::Domain(d)) => (
                    0,
                    Some(SocketAddr::new(
                        d.parse().expect("Failed to parse output ip address"),
                        port,
                    )),
                ),
                Some(Host::Ipv4(v4)) => (0, Some(SocketAddr::new(IpAddr::V4(v4), port))),
                Some(Host::Ipv6(v6)) => (0, Some(SocketAddr::new(IpAddr::V6(v6), port))),
            }
        };

        let output_local_addr = SocketAddr::new(addr_any, output_local_port);

        if output_url.scheme() == "udp" && output_addr.is_none() {
            panic!("Must designate a ip to send to to send UDP. Example: udp://127.0.0.1:1234, not udp://:1234");
        }

        match output_url.scheme() {
            "udp" => Box::new(future::ok::<
                Box<Sink<SinkItem = Bytes, SinkError = Error>>,
                Error,
            >(Box::new(
                UdpFramed::new(
                    UdpSocket::bind(&output_local_addr).unwrap(),
                    BytesCodec::new(),
                ).with(move |b| future::ok((b, output_addr.unwrap()))),
            ))),
            "srt" => Box::new(
                SrtSocketBuilder::new(
                    output_local_addr,
                    output_addr.map_or(ConnInitMethod::Listen, ConnInitMethod::Connect),
                ).build()
                    .unwrap()
                    .map(|c| -> Box<Sink<SinkItem = Bytes, SinkError = Error>> {
                        Box::new(c.sender())
                    }),
            ),
            s => panic!("unrecognized scheme: {} designated in output url", s),
        }
    };

    from.join(to)
        .and_then(|(from, to)| from.forward(to))
        .wait()
        .unwrap();
}
