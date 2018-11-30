use bytes::Bytes;
use clap::{App, Arg};
use failure::{bail, Error};
use futures::{future, prelude::*};
use srt::{ConnInitMethod, SrtSocketBuilder};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio_codec::BytesCodec;
use tokio_udp::{UdpFramed, UdpSocket};
use url::{Host, Url};

const AFTER_HELPTEXT: &str = r#"
Supported protocols:

UDP - send over a UDP port. 
    example:
        stransmit-rs
            udp://:1234          <- bind to interface 0.0.0.0:1234 and listen for data
            udp://127.0.0.1:2345 <- bind to interface 0.0.0.0:0 (any port) and send to 127.0.0.1:2345

    Settings:
    * interface=<ip address> the interface to bind to, defaults to all (0.0.0.0)

SRT - send over a SRT connection
    example:
        stransmit-rs
            srt://:1234          <- bind to interface 0.0.0.0:1234 and listen for a connection
            srt://127.0.0.1:1234 <- bind to interface 0.0.0.0:0 (any port) and try to connect to 127.0.0.1:1234

    Settings:
    * interface=<ip address> the interface to bind to, defaults to all (0.0.0.0)
    * latency_ms=<number>    the milliseconds of TSBPD latency to use
"#;

fn parse_args(args: &str) -> Result<HashMap<&str, &str>, Error> {
    let mut input_args = HashMap::new();

    if args.len() == 0 {
        return Ok(input_args);
    }

    for opt in args.split('&') {
        let mut key_val = opt.split('=');

        let key = match key_val.next() {
            Some(k) => k,
            None => {
                bail!("Failed to parse option {}", opt);
            }
        };

        let val = match key_val.next() {
            Some(v) => v,
            None => {
                bail!("Failed to parse option {}", opt);
            }
        };

        input_args.insert(key, val);
    }

    Ok(input_args)
}

fn add_srt_args<'a, 'b>(
    args: impl Iterator<Item = (&'a str, &'a str)>,
    builder: &'b mut SrtSocketBuilder,
) -> Result<(), Error> {
    for (k, v) in args {
        match k {
            "latency_ms" => builder.latency(Duration::from_millis(match v.parse() {
                Ok(i) => i,
                Err(e) => bail!(
                    "Failed to parse latency_ms parameter to input as integer: {:?}",
                    e
                ),
            })),
            "interface" => builder.local_addr(match v.parse() {
                Ok(local) => local,
                Err(e) => bail!("Failed to parse interface parameter as ip address: {:?}", e),
            }),
            unrecog => bail!("Unrecgonized parameter '{}' for srt", unrecog),
        };
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::init();

    let matches = App::new("stransmit_rs")
        .version("1.0")
        .author("Russell Greene")
        .about("SRT sender and receiver written in rust")
        .arg(
            Arg::with_name("FROM")
                .help("Sets the input url")
                .required(true),
        )
        .arg(
            Arg::with_name("TO")
                .help("Sets the output url")
                .required(true),
        )
        .after_help(AFTER_HELPTEXT)
        .get_matches();

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

        if input_url.scheme() == "udp" && input_local_port == 0 {
            panic!("Must not designate a ip to send to receive UDP. Example: udp://:1234, not udp://127.0.0.1:1234");
        }

        let args = parse_args(input_url.query().unwrap_or_default())?;

        match input_url.scheme() {
            "udp" => Box::new(
                future::ok::<Box<Stream<Item = Bytes, Error = Error>>, Error>(Box::new(
                    UdpFramed::new(
                        UdpSocket::bind(&SocketAddr::new(
                            args.get("interface").unwrap_or(&"0.0.0.0").parse()?,
                            input_local_port,
                        ))
                        .unwrap(),
                        BytesCodec::new(),
                    )
                    .map(|(b, _)| b.freeze())
                    .map_err(From::from),
                )),
            ),
            "srt" => {
                let mut builder = SrtSocketBuilder::new(
                    input_addr.map_or(ConnInitMethod::Listen, ConnInitMethod::Connect),
                );
                builder.local_port(input_local_port);

                add_srt_args(args.iter().map(|(&k, &v)| (k, v)), &mut builder)?;

                Box::new(builder.build().unwrap().map(
                    |c| -> Box<Stream<Item = Bytes, Error = Error>> {
                        Box::new(c.receiver().map(|(_, b)| b))
                    },
                ))
            }
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
        if output_url.scheme() == "udp" && output_addr.is_none() {
            panic!("Must designate a ip to send to to send UDP. Example: udp://127.0.0.1:1234, not udp://:1234");
        }

        let args = parse_args(output_url.query().unwrap_or_default())?;

        match output_url.scheme() {
            "udp" => Box::new(future::ok::<
                Box<Sink<SinkItem = Bytes, SinkError = Error>>,
                Error,
            >(Box::new(
                UdpFramed::new(
                    UdpSocket::bind(&SocketAddr::new(
                        args.get("interface").unwrap_or(&"0.0.0.0").parse()?,
                        0,
                    ))
                    .unwrap(),
                    BytesCodec::new(),
                )
                .with(move |b| future::ok((b, output_addr.unwrap()))),
            ))),
            "srt" => {
                let mut builder = SrtSocketBuilder::new(
                    output_addr.map_or(ConnInitMethod::Listen, ConnInitMethod::Connect),
                );
                builder.local_port(output_local_port);

                add_srt_args(args.iter().map(|(&k, &v)| (k, v)), &mut builder)?;
                Box::new(builder.build().unwrap().map(
                    |c| -> Box<Sink<SinkItem = Bytes, SinkError = Error>> {
                        Box::new(c.sender().with(|b| future::ok((Instant::now(), b))))
                    },
                ))
            }
            s => panic!("unrecognized scheme: {} designated in output url", s),
        }
    };

    from.join(to)
        .and_then(|(from, to)| from.forward(to))
        .wait()
        .unwrap();

    Ok(())
}
