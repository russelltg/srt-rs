mod streamer_server;

use std::{
    borrow::Cow,
    convert::TryInto,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    ops::Deref,
    path::Path,
    pin::Pin,
    process::exit,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, format_err, Error};
use bytes::Bytes;
use clap::{Arg, Command, ArgAction};
use log::info;
use url::{Host, Url};

use futures::{
    future,
    prelude::*,
    ready,
    stream::{self, once, unfold, BoxStream},
    try_join,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpListener,
    net::TcpStream,
    net::UdpSocket,
};
use tokio_util::{codec::BytesCodec, codec::Framed, codec::FramedWrite, udp::UdpFramed};

use srt_tokio::{
    options::{BindOptions, CallerOptions, ListenerOptions, RendezvousOptions, SocketOptions},
    SrtSocket,
};

use streamer_server::*;

const AFTER_HELPTEXT: &str = include_str!("helptext.txt");

// boxed() combinator for sink, which somehow doesn't exist
trait MySinkExt<Item>: Sink<Item> {
    fn boxed_sink<'a>(self) -> Pin<Box<dyn Sink<Item, Error = Self::Error> + 'a + Send>>
    where
        Self: Sized + Send + 'a,
    {
        Box::pin(self)
    }
}
impl<T, Item> MySinkExt<Item> for T where T: Sink<Item> {}

// INPUT and OUTPUT can be either a Url of a File
enum DataType<'a> {
    Url(Url),
    File(&'a Path),
}

fn read_to_stream(read: impl AsyncRead + Unpin) -> impl Stream<Item = Result<Bytes, Error>> {
    stream::unfold(read, |mut source| async move {
        let mut buf = [0; 1316];
        let bytes_read = match source.read(&mut buf[..]).await {
            Ok(0) => return None,
            Ok(bytes_read) => bytes_read,
            Err(e) => return Some((Err(Error::from(e)), source)),
        };

        Some((Ok(Bytes::copy_from_slice(&buf[..bytes_read])), source))
    })
}

fn parse_srt_args<C>(args: impl Iterator<Item = (C, C)>) -> Result<SocketOptions, Error>
where
    C: Deref<Target = str>,
{
    let mut key = false;
    let mut options = SocketOptions::default();
    for (k, v) in args {
        match &*k {
            "latency_ms" => {
                let latency = Duration::from_millis(match v.parse() {
                    Ok(i) => i,
                    Err(e) => bail!(
                        "Failed to parse latency_ms parameter to input as integer: {}",
                        e
                    ),
                });
                options.sender.peer_latency = latency;
                options.receiver.latency = latency;
            }
            "interface" => {
                options.connect.local.set_ip(match v.parse() {
                    Ok(local) => local,
                    Err(e) => bail!("Failed to parse interface parameter as ip address: {}", e),
                });
            }
            "local_port" => options.connect.local.set_port(match v.parse() {
                Ok(addr) => addr,
                Err(e) => bail!("Failed to parse local_port as a 16-bit integer: {}", e),
            }),
            "passphrase" => {
                options.encryption.passphrase = Some(v.to_string().try_into()?);
            }
            "pbkeylen" => {
                let size: u8 = v
                    .parse()
                    .map_err(|e| anyhow!("Failed to parse key length: {}", e))?;
                options.encryption.key_size = size.try_into()?;
                key = true;
            }
            "rendezvous" | "multiplex" | "autoreconnect" => (),
            unrecog => bail!("Unrecgonized parameter '{}' for srt", unrecog),
        }
    }
    if key && options.encryption.passphrase.is_none() {
        bail!("pbkeylen specified with no passphrase")
    }
    Ok(options)
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
        Some(Host::Domain(d)) if d.is_empty() => (port, None),

        // if host is specified, bind to 0
        Some(Host::Domain(d)) => (
            0,
            Some(
                match (d, port)
                    .to_socket_addrs()
                    .map(|mut it| it.find(SocketAddr::is_ipv4))
                {
                    Ok(Some(addr)) => addr,
                    Ok(None) => bail!("No socketaddrs in host {}", d),
                    Err(e) => bail!("Failed to parse host {}. Error: {}", d, e),
                },
            ),
        ),
        Some(Host::Ipv4(v4)) => (0, Some(SocketAddr::new(IpAddr::V4(v4), port))),
        Some(Host::Ipv6(v6)) => (0, Some(SocketAddr::new(IpAddr::V6(v6), port))),
    })
}

#[derive(Copy, Clone)]
enum ConnectionKind {
    Send,
    Listen(u16),
}

fn parse_connection_options<C>(
    args: impl Iterator<Item = (C, C)>,
    kind: ConnectionKind,
) -> Result<SocketAddr, Error>
where
    C: Deref<Target = str>,
{
    // defaults
    let mut addr = match kind {
        ConnectionKind::Send => "0.0.0.0:0".parse().unwrap(),
        ConnectionKind::Listen(port) => SocketAddr::new("0.0.0.0".parse().unwrap(), port),
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
            ("local_port", port, ConnectionKind::Send) => addr.set_port(match port.parse() {
                Ok(port) => port,
                Err(err) => bail!(
                    "Failed to parse local_port parameter '{}' as 16 bit integer: {}",
                    port,
                    err
                ),
            }),
            ("local_port", _, ConnectionKind::Listen(_)) => {
                bail!("local_port is incompatiable with udp listen mode")
            }
            (unrecog, _, _) => bail!("Unrecognized udp flag: {}", unrecog),
        }
    }

    Ok(addr)
}

fn parse_socket_options(
    input_url: &Url,
    input_addr: Option<SocketAddr>,
    input_local_port: u16,
) -> Result<BindOptions, Error> {
    let socket_options = parse_srt_args(input_url.query_pairs())?;

    let rendezvous_v = parse_rendezvous(input_url);

    let bind_options = match (input_addr, rendezvous_v.as_deref()) {
        // address but not rendezvous -> connect
        (Some(addr), None) => BindOptions::Call(CallerOptions::with(addr, None, socket_options)?),
        // no address or rendezvous -> listen
        (None, None) => {
            if input_url.query_pairs().any(|(a, _)| a == "local_port") {
                bail!("local_port is incompatible with listen connection technique")
            }
            BindOptions::Listen(ListenerOptions::with(input_local_port, socket_options)?)
        }
        // address and rendezvous flag -> rendezvous
        (Some(addr), Some("")) => {
            BindOptions::Rendezvous(RendezvousOptions::with(addr, socket_options)?)
        }
        // various invalid combinations
        (None, Some("")) => bail!("Cannot have rendezvous connection without host specified"),
        (_, Some(unex)) => bail!("Unexpected value for rendezvous: {}, expected empty", unex),
    };

    Ok(bind_options)
}

fn parse_rendezvous(input_url: &Url) -> Option<Cow<str>> {
    let rendezvous_v =
        input_url
            .query_pairs()
            .find_map(|(a, b)| if a == "rendezvous" { Some(b) } else { None });
    rendezvous_v
}

async fn make_srt_input(
    input_url: Url,
    input_addr: Option<SocketAddr>,
    input_local_port: u16,
) -> Result<BoxStream<'static, Bytes>, Error> {
    let bind_options = parse_socket_options(&input_url, input_addr, input_local_port);

    // make sure multiplex was not specified
    if input_url.query_pairs().any(|(k, _)| &*k == "multiplex") {
        bail!("multiplex is not a valid option for input urls");
    }

    Ok(SrtSocket::bind(bind_options?)
        .await?
        .map(Result::unwrap)
        .map(|(_, b)| b)
        .boxed())
}

fn resolve_input<'a>(
    input_url: DataType<'a>,
) -> Result<BoxStream<'static, Result<BoxStream<'static, Bytes>, Error>>, Error> {
    Ok(match input_url {
        DataType::Url(input_url) => {
            let (input_local_port, input_addr) = local_port_addr(&input_url, "input")?;
            match input_url.scheme() {
                "udp" if input_local_port == 0 => bail!(
                    "Must not designate a ip to receive UDP. \
                     Example: udp://:1234, not udp://127.0.0.1:1234. \
                     If you with to bind to a specific adapter, use the adapter setting instead."
                ),
                "udp" => once(async move {
                    Ok(UdpFramed::new(
                        UdpSocket::bind(&parse_connection_options(
                            input_url.query_pairs(),
                            ConnectionKind::Listen(input_local_port),
                        )?)
                        .await?,
                        BytesCodec::new(),
                    )
                    .map(Result::unwrap)
                    .map(|(b, _)| b.freeze())
                    .boxed())
                })
                .boxed(),
                "srt" => {
                    if input_url.query_pairs().any(|(k, _)| k == "autoreconnect") {
                        unfold(
                            (input_addr, input_url, input_local_port),
                            move |(input_addr, input_url, input_local_port)| async move {
                                Some((
                                    make_srt_input(input_url.clone(), input_addr, input_local_port)
                                        .await,
                                    (input_addr, input_url, input_local_port),
                                ))
                            },
                        )
                        .boxed()
                    } else {
                        once(make_srt_input(input_url, input_addr, input_local_port)).boxed()
                    }
                }
                "tcp" => {
                    if let Some(input) = input_addr {
                        once(async move {
                            loop {
                                match TcpStream::connect(input).await {
                                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                                    Ok(stream) => {
                                        return Ok(Framed::new(stream, BytesCodec::new())
                                            .map(Result::unwrap)
                                            .map(|b| b.freeze())
                                            .boxed())
                                    }
                                }
                            }
                        })
                        .boxed()
                    } else {
                        once(async move {
                            let input = &parse_connection_options(
                                input_url.query_pairs(),
                                ConnectionKind::Listen(input_local_port),
                            )?;
                            let listener = TcpListener::bind(input).await?;
                            let (stream, _) = listener.accept().await?;
                            Ok(Framed::new(stream, BytesCodec::new())
                                .map(Result::unwrap)
                                .map(|b| b.freeze())
                                .boxed())
                        })
                        .boxed()
                    }
                }
                s => bail!("unrecognized scheme: {} designated in input url", s),
            }
        }
        DataType::File(file) if file == Path::new("-") => once(async move {
            Ok(read_to_stream(tokio::io::stdin())
                .map(Result::unwrap)
                .boxed())
        })
        .boxed(),
        DataType::File(file) => {
            let file = file.to_owned();
            once(async move {
                let f = tokio::fs::File::open(file).await?;

                Ok(read_to_stream(f).map(Result::unwrap).boxed())
            })
            .boxed()
        }
    })
}

type BoxSink = Pin<Box<dyn Sink<Bytes, Error = Error> + Send>>;
type SinkStream = BoxStream<'static, Result<BoxSink, Error>>;

async fn make_srt_ouput(
    output_addr: Option<SocketAddr>,
    output_url: Url,
    output_local_port: u16,
) -> Result<BoxSink, Error> {
    let bind_options = parse_socket_options(&output_url, output_addr, output_local_port)?;

    let is_multiplex = match (
        output_url
            .query_pairs()
            .find(|(k, _)| k == "multiplex")
            .as_ref()
            .map(|(_, v)| &**v),
        &bind_options,
    ) {
        // OK
        (Some(""), BindOptions::Listen(options)) => Some(options),
        (None, _) => None,

        // not OK
        (Some(""), _) => bail!("The multiplex option is only supported for listen connections"),
        (Some(a), _) => bail!("Unexpected value for multiplex: {}", a),
    };

    match is_multiplex {
        Some(options) => Ok(StreamerServer::bind(options.clone())
            .await?
            .with(|b| future::ok((Instant::now(), b)))
            .boxed_sink()),
        None => Ok(SrtSocket::bind(bind_options)
            .await?
            .with(|b| future::ok((Instant::now(), b)))
            .boxed_sink()),
    }
}

fn resolve_output(output_url: DataType) -> Result<SinkStream, Error> {
    Ok(match output_url {
        DataType::Url(output_url) => {
            let (output_local_port, output_addr) = local_port_addr(&output_url, "output")?;
            match output_url.scheme() {
                "udp" if output_addr.is_none() => bail!(
                    "Must designate a ip to send to to send UDP. \
                     Example: udp://127.0.0.1:1234, not udp://:1234"
                ),
                "udp" => once(async move {
                    Ok(UdpFramed::new(
                        UdpSocket::bind(&parse_connection_options(
                            output_url.query_pairs(),
                            ConnectionKind::Send,
                        )?)
                        .await?,
                        BytesCodec::new(),
                    )
                    .with(move |b| future::ready(Ok((b, output_addr.unwrap()))))
                    .boxed_sink())
                })
                .boxed(),
                "srt" => {
                    if output_url.query_pairs().any(|(k, _)| k == "autoreconnect") {
                        unfold(
                            (output_addr, output_url, output_local_port),
                            |(output_addr, output_url, output_local_port)| async move {
                                Some((
                                    make_srt_ouput(
                                        output_addr,
                                        output_url.clone(),
                                        output_local_port,
                                    )
                                    .await,
                                    (output_addr, output_url, output_local_port),
                                ))
                            },
                        )
                        .boxed()
                    } else {
                        once(make_srt_ouput(output_addr, output_url, output_local_port)).boxed()
                    }
                }
                "tcp" => {
                    if let Some(output) = output_addr {
                        once(async move {
                            loop {
                                match TcpStream::connect(output).await {
                                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                                    Ok(stream) => {
                                        return Ok(Framed::new(stream, BytesCodec::new())
                                            .with(move |b| future::ready(Ok(b)))
                                            .boxed_sink())
                                    }
                                }
                            }
                        })
                        .boxed()
                    } else {
                        once(async move {
                            let output = &parse_connection_options(
                                output_url.query_pairs(),
                                ConnectionKind::Listen(output_local_port),
                            )?;
                            let listener = TcpListener::bind(output).await?;
                            let (stream, _) = listener.accept().await?;
                            Ok(Framed::new(stream, BytesCodec::new())
                                .with(move |b| future::ready(Ok(b)))
                                .boxed_sink())
                        })
                        .boxed()
                    }
                }
                s => bail!("unrecognized scheme '{}' designated in output url", s),
            }
        }
        DataType::File(file) if file == Path::new("-") => once(async move {
            Ok(FramedWrite::new(tokio::io::stdout(), BytesCodec::new())
                .with(move |b| future::ready(Ok(b)))
                .boxed_sink())
        })
        .boxed(),
        DataType::File(file) => {
            let file = file.to_owned();
            once(async move {
                let output = tokio::fs::File::create(file).await?;
                Ok(FramedWrite::new(output, BytesCodec::new())
                    .with(move |b| future::ready(Ok(b)))
                    .boxed_sink())
            })
            .boxed()
        }
    })
}

// Flatten a list of streams of sinks into a single sink that sends to the available sinks
struct MultiSinkFlatten {
    sinks: Vec<(Option<SinkStream>, Option<BoxSink>)>,
}

impl MultiSinkFlatten {
    fn new(from: impl Iterator<Item = BoxStream<'static, Result<BoxSink, Error>>>) -> Self {
        MultiSinkFlatten {
            sinks: from.map(|str| (Some(str), None)).collect(),
        }
    }
}

impl Sink<Bytes> for MultiSinkFlatten {
    type Error = Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut ret = Poll::Ready(Err(format_err!("All sinks ended permanantly")));
        for (ref mut stream_opt, ref mut sink_opt) in &mut self.as_mut().sinks {
            // loop until we get a pending or ready
            let poll_result = loop {
                // poll the existing sink
                match (stream_opt.as_mut(), sink_opt.as_mut()) {
                    (_, Some(sink)) => {
                        match sink.as_mut().poll_ready(cx) {
                            Poll::Pending => break Poll::Pending,
                            Poll::Ready(Ok(_)) => break Poll::Ready(Ok(())),
                            Poll::Ready(Err(e)) => {
                                info!("Sink closed {:?}", e);
                                // sink closed, restart conn init
                                *sink_opt = None;
                            }
                        }
                    }
                    (Some(stream), None) => {
                        // xxx not ? here!
                        match stream.as_mut().try_poll_next(cx)? {
                            Poll::Ready(Some(sink)) => {
                                *sink_opt = Some(sink);
                            }
                            Poll::Ready(None) => *stream_opt = None,
                            Poll::Pending => break Poll::Pending,
                        }
                    }
                    (None, None) => break Poll::Ready(Err(())),
                }
            };

            // update result with the "logical max" of ret and poll_result, Ready::Ok > Pending > Ready::Err
            match (&ret, poll_result) {
                (_, Poll::Ready(Ok(()))) => ret = Poll::Ready(Ok(())), // Ready(Ok) trumps all
                (Poll::Ready(Err(_)), Poll::Pending) => ret = Poll::Pending, // Pending trumps Ready(Err)
                _ => {}                                                      // nothing to do
            }
        }

        ret
    }
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        for sink in &mut self
            .as_mut()
            .sinks
            .iter_mut()
            .filter_map(|(_, s)| s.as_mut())
        {
            sink.as_mut().start_send(item.clone())?; // xxx not ?
        }
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        for sink in &mut self
            .as_mut()
            .sinks
            .iter_mut()
            .filter_map(|(_, s)| s.as_mut())
        {
            ready!(sink.as_mut().poll_flush(cx))?; // xxx not ?
        }
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        for sink in &mut self
            .as_mut()
            .sinks
            .iter_mut()
            .filter_map(|(_, s)| s.as_mut())
        {
            ready!(sink.as_mut().poll_close(cx))?; // xxx not ?
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!(
            "Invalid settings detected: {}\n\nSee srt-transmit --help for more info",
            e
        );
        exit(1);
    }
}

async fn run() -> Result<(), Error> {
    pretty_env_logger::formatted_builder()
        // .format(|buf, record| writeln!(buf, "{} [{}] {}", record.args()))
        .format_timestamp_micros()
        .init();

    let app = Command::new("srt-transmit")
        .version("1.0")
        .author("Russell Greene")
        .about("SRT sender and receiver written in rust");

    #[cfg(feature = "console-subscriber")]
    let app = app.arg(Arg::new("console").long("console"));

    let matches = app
        .arg(Arg::new("FROM").help("Sets the input url").required(true))
        .arg(
            Arg::new("TO")
                .help("Sets the output url")
                .required(true)
                .action(ArgAction::Append)
        )
        .after_help(AFTER_HELPTEXT)
        .get_matches();

    #[cfg(feature = "console-subscriber")]
    if matches.is_present("console") {
        console_subscriber::init();
    }

    // these are required parameters, so unwrapping them is safe
    let from_str: &String = matches.get_one("FROM").unwrap();
    let input_url = match Url::parse(from_str) {
        Err(_) => DataType::File(Path::new(from_str)),
        Ok(url) => DataType::Url(url),
    };
    let to_strs = matches.get_many("TO").unwrap();
    let output_urls_iter = to_strs.map(|to_str: &String| match Url::parse(to_str) {
        Err(_) => DataType::File(Path::new(to_str)),
        Ok(url) => DataType::Url(url),
    });

    // Resolve the receiver side
    // this will be a future that resolves to a stream of bytes
    // (all boxed to allow for different protocols)
    let mut stream_stream = resolve_input(input_url)?;

    // Resolve the sender side
    // similar to the receiver side, except a sink instead of a stream
    let mut sink_streams = vec![];
    for to in output_urls_iter.map(resolve_output) {
        sink_streams.push(to?);
    }

    let mut sinks = MultiSinkFlatten::new(sink_streams.drain(..));

    // poll sink and stream in parallel, only yielding when there is something ready for the sink and the stream is good.
    while let (_, Some(stream)) = try_join!(
        future::poll_fn(|cx| Pin::new(&mut sinks).poll_ready(cx)),
        stream_stream.try_next()
    )? {
        // let a: () = &mut *stream;
        sinks.send_all(&mut stream.map(Ok)).await?;
    }

    sinks.close().await?;
    Ok(())
}
