use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::path::Path;
use std::process::exit;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use clap::{App, Arg};
use failure::{bail, Error};
use futures::{future, prelude::*, try_ready, Poll, StartSend};
use tokio_codec::BytesCodec;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_udp::{UdpFramed, UdpSocket};
use url::{Host, Url};

use srt::{ConnInitMethod, SrtSocketBuilder, StreamerServer};

const AFTER_HELPTEXT: &str = r#"
Supported protocols:

UDP - send over a UDP port. 
    example:
        stransmit-rs \
            udp://:1234 \
            # ^- bind to interface 0.0.0.0:1234 and listen for data \
            udp://127.0.0.1:2345 \
            # ^- bind to interface 0.0.0.0:0 (any port) and send to 127.0.0.1:2345

    Connection modes:
    * listen: bind to a local port. Can only be used for receiving 
      data (first parameter). Is specified by leaving out host in the url:
          udp://:1234
          ^- bind to port 1234,  waiting for data

          udp://:1234?interface=127.0.0.1  
          ^- bind to port 1234 on loopback interface, waiting for data

    * send: send to a remote host. Can only be used for sending data
      (second parameter). Is specified by including a host in the url:
          udp://127.0.0.1:2000
          ^- bind to port 0 (an ephemeral port), and send data to 127.0.0.1:2000

          udp://127.0.0.1:2000?local_port=3000
          ^- bind to port 3000 and send data to 127.0.0.1:2000 

    Settings:
    * interface=<ip address> the interface to bind to, defaults to 0.0.0.0
    * local_port=<number>    the local port to bind to. Only applicable for
                             send connection mode


SRT - send over a SRT connection
    example:
        stransmit-rs \
            srt://:1234 \
            # ^- bind to interface 0.0.0.0:1234 and listen for a connection \
            #    with 2 seconds of tsbpd latency \
            srt://127.0.0.1:1235 \
            # ^- bind to interface 0.0.0.0:0 (any port, unless local_port is 
            #    specified) and try to connect to 127.0.0.1:1235

    Connection modes:
    * listen: listen for a connecter. Can be used for either sending or
      receiving data. Is specified by leaving out host in the url:
          srt://:1234
          ^- bind to port 1234, waiting for a connector. Uses the connecter's 
             latency
          
          srt://:1234?latency_ms=2000 
          ^-bind to port 1234 and advertise a latency of 2000.

    * connect: connect to a listener. Can be used for either sending or
      receiving data. Is specified by including a host in the url:
          srt://127.0.0.1:1234?latency_ms=1000     
          ^- bind to port 0 (an epheeral port), and connect to 127.0.0.1:1234,
             advertising a 1s latency
          
          srt://127.0.0.1:1234?local_port=3000  
          ^- bind to port 3000 and connect to 127.0.0.1:123
        
    * rendezvous: connect to another rendezvous connecter. This is useful if 
      both sides are behind a NAT, in which case the host needs to be the 
      public IP and port. Is specified by including the rendezvous flag:
          srt://example.com:1234?rendezvous
          ^- bind to port 1234 and connect to example.com:1234

          srt://example.com:1234?rendezvous&local_port=2000
          ^- bind to port 2000 and connect to example.com:1234


    Settings:
    * interface=<ip address>  the interface to bind to, defaults to all (0.0.0.0)
    * latency_ms=<number>     the milliseconds of TSBPD latency to use. If both 
                              sides set this, the higher setting is used
    * rendezvous              use the rendezvous connection method
    * local_port=<number>     the local port to bind to. Only applicable for 
                              rendezvous and connect connection modes
    * multiplex               allow multiple connections on the single port, only
                              applicable for listen connection mode, in the sender
                              position
FILE - save or send a file
    example:
        stransmit-rs \
            ./a.txt \
            # ^- send a.txt \
            udp://127.0.0.1:2000
            # ^- to a udp port

    You can use the special - file to redirect from/to stdin/stdout:

    example:
        stransmit-rs \
            - \
            # ^- get data from stdin \
            srt://:2000
            # ^- send data over SRT on port 2000

"#;

struct MultiSink<I> {
    sinks: Vec<Box<dyn Sink<SinkItem = I, SinkError = Error> + Send>>,
}

impl<I: Clone> Sink for MultiSink<I> {
    type SinkItem = I;
    type SinkError = Error;

    fn start_send(&mut self, item: I) -> StartSend<I, Error> {
        for s in &mut self.sinks {
            // just discard the result, don't send that packet
            let _ = s.start_send(item.clone())?;
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        for s in &mut self.sinks {
            try_ready!(s.poll_complete());
        }
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), Error> {
        for s in &mut self.sinks {
            try_ready!(s.poll_complete());
        }
        Ok(Async::Ready(()))
    }
}

// INPUT and OUTPUT can be either a Url of a File
enum DataType<'a> {
    Url(Url),
    File(&'a Path),
}

// Stream/Sink implementaton for primatives that only implement AsyncRead/AsyncWrite
// not sure why this doesn't already exist in tokio.
struct StreamWriteRead<T> {
    file: T,
    buffer: BytesMut,
}

impl<T> StreamWriteRead<T> {
    fn new(file: T) -> Self {
        Self {
            file,
            buffer: BytesMut::from(vec![0; 4096]),
        }
    }
}

impl<T: AsyncRead> Stream for StreamWriteRead<T> {
    type Error = Error;
    type Item = Bytes;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let num_read = try_ready!(self.file.poll_read(&mut self.buffer[..]));

        if num_read == 0 {
            return Ok(Async::Ready(None));
        }

        let mut a = BytesMut::from(vec![0; 4096]);
        mem::swap(&mut self.buffer, &mut a);

        Ok(Async::Ready(Some(a.split_to(num_read).clone().freeze())))
    }
}

impl<T: AsyncWrite> Sink for StreamWriteRead<T> {
    type SinkError = Error;
    type SinkItem = Bytes;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        match self.file.poll_write(&item[..])? {
            Async::Ready(_) => Ok(AsyncSink::Ready),
            Async::NotReady => Ok(AsyncSink::NotReady(item)),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        Ok(self.file.poll_flush()?)
    }
}

fn add_srt_args<C>(
    args: impl Iterator<Item = (C, C)>,
    builder: &mut SrtSocketBuilder,
) -> Result<(), Error>
where
    C: Deref<Target = str>,
{
    for (k, v) in args {
        match &*k {
            "latency_ms" => builder.latency(Duration::from_millis(match v.parse() {
                Ok(i) => i,
                Err(e) => bail!(
                    "Failed to parse latency_ms parameter to input as integer: {}",
                    e
                ),
            })),
            "interface" => builder.local_addr(match v.parse() {
                Ok(local) => local,
                Err(e) => bail!("Failed to parse interface parameter as ip address: {}", e),
            }),
            "local_port" => match builder.conn_type() {
                ConnInitMethod::Listen => {
                    bail!("local_port is incompatible with listen connection technique")
                }
                _ => builder.local_port(match v.parse() {
                    Ok(addr) => addr,
                    Err(e) => bail!("Failed to parse local_port as a 16-bit integer: {}", e),
                }),
            },
            // this has already been handled, ignore
            "rendezvous" => builder,
            "multiplex" => builder,
            unrecog => bail!("Unrecgonized parameter '{}' for srt", unrecog),
        };
    }

    Ok(())
}

// get the local port and address from the input url
// kind is to put in error messages, "input", or "output"
fn local_port_addr(url: &Url, kind: &str) -> Result<(u16, Option<SocketAddr>), Error> {
    let port = match url.port() {
        None => bail!("{} URL has no port specified", kind),
        Some(port) => port,
    };

    Ok(match url.host() {
        // no host means bind to the port specified
        None => (port, None),
        Some(Host::Domain(d)) if d == "" => (port, None),

        // if host is specified, bind to 0
        Some(Host::Domain(d)) => (
            0,
            Some(SocketAddr::new(
                match d.parse() {
                    Ok(addr) => addr,
                    Err(err) => bail!("Failed to parse {} ip address: {}", kind, err),
                },
                port,
            )),
        ),
        Some(Host::Ipv4(v4)) => (0, Some(SocketAddr::new(IpAddr::V4(v4), port))),
        Some(Host::Ipv6(v6)) => (0, Some(SocketAddr::new(IpAddr::V6(v6), port))),
    })
}

fn get_conn_init_method(
    addr: Option<SocketAddr>,
    rendezvous_v: Option<&str>,
) -> Result<ConnInitMethod, Error> {
    Ok(match (addr, rendezvous_v) {
        // address but not rendezvous -> connect
        (Some(addr), None) => ConnInitMethod::Connect(addr),
        // no address or rendezvous -> listen
        (None, None) => ConnInitMethod::Listen,
        // address and rendezvous flag -> rendezvous
        (Some(addr), Some("")) => ConnInitMethod::Rendezvous(addr),
        // various invalid combinations
        (None, Some("")) => bail!("Cannot have rendezvous connection without host specified"),
        (_, Some(unex)) => bail!("Unexpected value for rendezvous: {}, expected empty", unex),
    })
}

#[derive(Copy, Clone)]
enum UdpKind {
    Send,
    Listen(u16),
}

fn parse_udp_options<C>(
    args: impl Iterator<Item = (C, C)>,
    kind: UdpKind,
) -> Result<SocketAddr, Error>
where
    C: Deref<Target = str>,
{
    // defaults
    let mut addr = match kind {
        UdpKind::Send => "0.0.0.0:0".parse().unwrap(),
        UdpKind::Listen(port) => SocketAddr::new("0.0.0.0".parse().unwrap(), port),
    };

    for (k, v) in args {
        match (&*k, &*v, kind) {
            ("interface", interface, _) => addr.set_ip(match interface.parse() {
                Ok(ip) => ip,
                Err(err) => bail!(
                    "Failed to parse interface parameter '{}' as an IP: {}",
                    interface,
                    err
                ),
            }),
            ("local_port", port, UdpKind::Send) => addr.set_port(match port.parse() {
                Ok(port) => port,
                Err(err) => bail!(
                    "Failed to parse local_port parameter '{}' as 16 bit integer: {}",
                    port,
                    err
                ),
            }),
            ("local_port", _, UdpKind::Listen(_)) => {
                bail!("local_port is incompatiable with udp listen mode")
            }
            (unrecog, _, _) => bail!("Unrecognized udp flag: {}", unrecog),
        }
    }

    Ok(addr)
}

fn resolve_input<'a>(
    input_url: DataType<'a>,
) -> Result<
    Box<
        dyn Future<Item = Box<dyn Stream<Item = Bytes, Error = Error> + Send>, Error = Error>
            + Send,
    >,
    Error,
> {
    Ok(match input_url {
        DataType::Url(input_url) => {
            let (input_local_port, input_addr) = local_port_addr(&input_url, "input")?;
            match input_url.scheme() {
                    "udp" if input_local_port == 0 => 
                        bail!("Must not designate a ip to receive UDP. Example: udp://:1234, not udp://127.0.0.1:1234. If you with to bind to a specific adapter, use the adapter setting instead."),
                    "udp" => {
                        Box::new(future::ok::<
                            Box<dyn Stream<Item = Bytes, Error = Error> + Send>,
                            Error,
                        >(Box::new(
                            UdpFramed::new(
                                UdpSocket::bind(&parse_udp_options(
                                    input_url.query_pairs(),
                                    UdpKind::Listen(input_local_port),
                                )?)?,
                                BytesCodec::new(),
                            )
                            .map(|(b, _)| b.freeze())
                            .map_err(From::from),
                        )))
                    }
                    "srt" => {
                        let mut builder = SrtSocketBuilder::new(get_conn_init_method(
                            input_addr,
                            input_url
                                .query_pairs()
                                .find_map(|(a, b)| if a == "rendezvous" { Some(b) } else { None })
                                .as_ref()
                                .map(|a| &**a),
                        )?);
                        builder.local_port(input_local_port);

                        add_srt_args(input_url.query_pairs(), &mut builder)?;

                        // make sure multiplex was not specified
                        if input_url.query_pairs().any(|(k, _)| &*k == "multiplex") {
                            bail!("multiplex is not a valid option for input urls");
                        }

                        Box::new(builder.build()?.map(
                            |c| -> Box<dyn Stream<Item = Bytes, Error = Error> + Send> {
                                Box::new(c.receiver().map(|(_, b)| b))
                            },
                        ))
                    }
                    s => bail!("unrecognized scheme: {} designated in input url", s),
                }
        }
        DataType::File(file) => {
            if file == Path::new("-") {
                Box::new(future::ok::<
                    Box<dyn Stream<Item = Bytes, Error = Error> + Send>,
                    Error,
                >(Box::new(StreamWriteRead::new(
                    tokio_fs::stdin(),
                ))))
            } else {
                let file_fut = tokio_fs::File::open(file.to_owned());

                Box::new(
                    file_fut
                        .map(|f| -> Box<dyn Stream<Item = Bytes, Error = Error> + Send> {
                            Box::new(StreamWriteRead::new(f))
                        })
                        .map_err(Error::from),
                )
            }
        }
    })
}

fn resolve_output<'a>(
    output_url: DataType<'a>,
) -> Result<
    Box<
        dyn Future<Item = Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send>, Error = Error>
            + Send,
    >,
    Error,
> {
    Ok(match output_url {
        DataType::Url(output_url) => {
            let (output_local_port, output_addr) = local_port_addr(&output_url, "output")?;

            match output_url.scheme() {
                    "udp" if output_addr.is_none() => 
                        bail!("Must designate a ip to send to to send UDP. Example: udp://127.0.0.1:1234, not udp://:1234"),
                    "udp" => Box::new(future::ok::<
                        Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send>,
                        Error,
                    >(Box::new(
                        UdpFramed::new(
                            UdpSocket::bind(&parse_udp_options(
                                output_url.query_pairs(),
                                UdpKind::Send,
                            )?)?,
                            BytesCodec::new(),
                        )
                        .with(move |b| future::ok((b, output_addr.unwrap()))),
                    ))),
                    "srt" => {
                        let mut builder = SrtSocketBuilder::new(get_conn_init_method(
                            output_addr,
                            output_url
                                .query_pairs()
                                .find_map(|(a, b)| if a == "rendezvous" { Some(b) } else { None })
                                .as_ref()
                                .map(|a| &**a),
                        )?);
                        builder.local_port(output_local_port);

                        let is_multiplex = match (
                            output_url
                                .query_pairs()
                                .find(|(k, _)| k == "multiplex")
                                .as_ref()
                                .map(|(_, v)| &**v),
                            builder.conn_type(),
                        ) {
                            // OK
                            (Some(""), ConnInitMethod::Listen) => true,
                            (None, _) => false,

                            // not OK
                            (Some(""), _) => bail!(
                                "The multiplex option is only supported for listen connections"
                            ),
                            (Some(a), _) => bail!("Unexpected value for multiplex: {}", a),
                        };

                        add_srt_args(output_url.query_pairs(), &mut builder)?;

                        if is_multiplex {
                            let boxed: Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send> =
                                Box::new(
                                    StreamerServer::new(builder.build_multiplexed()?)
                                        .with(|b| future::ok((Instant::now(), b))),
                                );

                            Box::new(future::ok(boxed))
                        } else {
                            Box::new(builder.build()?.map(
                                |c| -> Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send> {
                                    Box::new(c.sender().with(|b| future::ok((Instant::now(), b))))
                                },
                            ))
                        }
                    }
                    s => bail!("unrecognized scheme: {} designated in output url", s),
                }
        }
        DataType::File(file) => {
            if file == Path::new("-") {
                Box::new(future::ok::<
                    Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send>,
                    Error,
                >(Box::new(StreamWriteRead::new(
                    tokio_fs::stdout(),
                ))))
            } else {
                let file_fut = tokio_fs::File::create(file.to_owned());
                Box::new(
                    file_fut
                        .map(
                            |f| -> Box<dyn Sink<SinkItem = Bytes, SinkError = Error> + Send> {
                                Box::new(StreamWriteRead::new(f))
                            },
                        )
                        .map_err(Error::from),
                )
            }
        }
    })
}

fn main() {
    if let Err(e) = run() {
        eprintln!(
            "Invalid settings detected: {}\n\nSee stransmit-rs --help for more info",
            e
        );
        exit(1);
    }
}

fn run() -> Result<(), Error> {
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
                .required(true)
                .multiple(true),
        )
        .after_help(AFTER_HELPTEXT)
        .get_matches();

    // these are required parameters, so unwrapping them is safe
    let from_str = matches.value_of("FROM").unwrap();
    let input_url = match Url::parse(from_str) {
        Err(_) => DataType::File(Path::new(from_str)),
        Ok(url) => DataType::Url(url),
    };
    let to_strs = matches.values_of("TO").unwrap();
    let output_urls_iter = to_strs.map(|to_str| match Url::parse(to_str) {
        Err(_) => DataType::File(Path::new(to_str)),
        Ok(url) => DataType::Url(url),
    });

    // Resolve the receiver side
    // this will be a future that resolves to a stream of bytes
    // (all boxed to allow for different protocols)
    let from = resolve_input(input_url)?;

    // Resolve the sender side
    // similar to the receiver side, except a sink instead of a stream
    let to_iter = output_urls_iter
        .map(resolve_output)
        .collect::<Result<Vec<_>, _>>()?;

    tokio::run(
        from.join(future::join_all(to_iter.into_iter()))
            .and_then(|(from, to_vec)| from.forward(MultiSink { sinks: to_vec }))
            .map(|_| ())
            .map_err(|e| panic!("{:?}", e)),
    );

    Ok(())
}
