use std::{
    io,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::Path,
    pin::Pin,
    process::exit,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{bail, format_err, Error};
use bytes::Bytes;
use clap::{App, Arg};
use url::{Host, Url};

use futures::{
    future,
    prelude::*,
    ready,
    stream::{self, once, unfold, BoxStream},
    try_join,
};
use tokio::{io::AsyncReadExt, net::UdpSocket, prelude::AsyncRead};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};

use log::info;
use srt::{ConnInitMethod, SrtSocketBuilder, StreamerServer};

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

// futures::AsyncWrite impl for tokio::io::AsyncWrite
struct FutAsyncWrite<T>(T);
impl<T: tokio::io::AsyncWrite + Unpin> futures::AsyncWrite for FutAsyncWrite<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        <T as tokio::io::AsyncWrite>::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        <T as tokio::io::AsyncWrite>::poll_flush(Pin::new(&mut self.0), cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        <T as tokio::io::AsyncWrite>::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

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

fn add_srt_args<C>(
    args: impl Iterator<Item = (C, C)>,
    mut builder: SrtSocketBuilder,
) -> Result<SrtSocketBuilder, Error>
where
    C: Deref<Target = str>,
{
    let mut crypto: Option<(u8, String)> = None;
    for (k, v) in args {
        match &*k {
            "latency_ms" => {
                builder = builder.latency(Duration::from_millis(match v.parse() {
                    Ok(i) => i,
                    Err(e) => bail!(
                        "Failed to parse latency_ms parameter to input as integer: {}",
                        e
                    ),
                }))
            }
            "interface" => {
                builder = builder.local_addr(match v.parse() {
                    Ok(local) => local,
                    Err(e) => bail!("Failed to parse interface parameter as ip address: {}", e),
                })
            }
            "local_port" => match builder.conn_type() {
                ConnInitMethod::Listen => {
                    bail!("local_port is incompatible with listen connection technique")
                }
                _ => {
                    builder = builder.local_port(match v.parse() {
                        Ok(addr) => addr,
                        Err(e) => bail!("Failed to parse local_port as a 16-bit integer: {}", e),
                    })
                }
            },
            "passphrase" => match &mut crypto {
                Some((_, ref mut pw)) => *pw = (&*v).into(),
                None => crypto = Some((16, (&*v).into())),
            },
            "pbkeylen" => {
                let kl = match v.parse() {
                    Ok(i @ 16) | Ok(i @ 24) | Ok(i @ 32) => i,
                    Ok(invalid) => bail!("Invalid key length {}, must be 16, 24, or 32", invalid),
                    Err(e) => bail!("Failed to parse key length: {}", e),
                };
                match &mut crypto {
                    Some((ref mut sz, _)) => *sz = kl,
                    None => crypto = Some((kl, "".into())),
                }
            }
            // this has already been handled, ignore
            "rendezvous" | "multiplex" | "autoreconnect" => (),
            unrecog => bail!("Unrecgonized parameter '{}' for srt", unrecog),
        };
    }
    if let Some((sz, pw)) = crypto {
        if pw.is_empty() {
            bail!("pbkeylen specified with no passphrase");
        }
        builder = builder.crypto(sz, pw);
    }

    Ok(builder)
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

async fn make_srt_input(
    input_addr: Option<SocketAddr>,
    input_url: Url,
    input_local_port: u16,
) -> Result<BoxStream<'static, Bytes>, Error> {
    let mut builder = SrtSocketBuilder::new(get_conn_init_method(
        input_addr,
        input_url
            .query_pairs()
            .find_map(|(a, b)| if a == "rendezvous" { Some(b) } else { None })
            .as_deref(),
    )?)
    .local_port(input_local_port);

    builder = add_srt_args(input_url.query_pairs(), builder)?;

    // make sure multiplex was not specified
    if input_url.query_pairs().any(|(k, _)| &*k == "multiplex") {
        bail!("multiplex is not a valid option for input urls");
    }
    Ok(builder
        .connect()
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
                    "udp" if input_local_port == 0 => 
                        bail!("Must not designate a ip to receive UDP. Example: udp://:1234, not udp://127.0.0.1:1234. If you with to bind to a specific adapter, use the adapter setting instead."),
                    "udp" => {
                        once(async move {
                            Ok(UdpFramed::new(
                                UdpSocket::bind(&parse_udp_options(
                                    input_url.query_pairs(),
                                    UdpKind::Listen(input_local_port),
                                )?).await?,
                                BytesCodec::new(),
                            ).map(Result::unwrap).map(|(b, _)| b.freeze()).boxed())
                        }).boxed()
                    }
                    "srt" => {
                        if input_url.query_pairs().any(|(k, _)| k == "autoreconnect") {
                            unfold((input_addr, input_url, input_local_port), move |(input_addr, input_url, input_local_port)| async move { Some((make_srt_input(input_addr, input_url.clone(), input_local_port).await, (input_addr, input_url, input_local_port))) }).boxed()
                        } else {
                            once(make_srt_input(input_addr, input_url, input_local_port)).boxed()
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
    let builder = SrtSocketBuilder::new(get_conn_init_method(
        output_addr,
        output_url
            .query_pairs()
            .find_map(|(a, b)| if a == "rendezvous" { Some(b) } else { None })
            .as_deref(),
    )?)
    .local_port(output_local_port);

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
        (Some(""), _) => bail!("The multiplex option is only supported for listen connections"),
        (Some(a), _) => bail!("Unexpected value for multiplex: {}", a),
    };
    let builder = add_srt_args(output_url.query_pairs(), builder)?;

    if is_multiplex {
        Ok(StreamerServer::new(builder.build_multiplexed().await?)
            .with(|b| future::ok((Instant::now(), b)))
            .boxed_sink())
    } else {
        Ok(builder
            .connect()
            .await?
            .with(|b| future::ok((Instant::now(), b)))
            .boxed_sink())
    }
}

fn resolve_output(output_url: DataType) -> Result<SinkStream, Error> {
    Ok(match output_url {
        DataType::Url(output_url) => {
            let (output_local_port, output_addr) = local_port_addr(&output_url, "output")?;

            match output_url.scheme() {
                    "udp" if output_addr.is_none() => 
                        bail!("Must designate a ip to send to to send UDP. Example: udp://127.0.0.1:1234, not udp://:1234"),
                    "udp" => once(async move {
                        Ok(UdpFramed::new(
                            UdpSocket::bind(&parse_udp_options(
                                output_url.query_pairs(),
                                UdpKind::Send,
                            )?).await?,
                            BytesCodec::new(),
                        )
                        .with(move |b| future::ready(Ok((b, output_addr.unwrap())))).boxed_sink())
                    }).boxed(),
                    "srt" => {
                        if output_url.query_pairs().any(|(k, _)| k == "autoreconnect") {
                            unfold((output_addr, output_url, output_local_port), |(output_addr, output_url, output_local_port)| async move { Some((make_srt_ouput(output_addr, output_url.clone(), output_local_port).await, (output_addr, output_url, output_local_port))) }).boxed()
                        } else {
                            once(make_srt_ouput(output_addr, output_url, output_local_port)).boxed()
                        }
                    },
                  s => bail!("unrecognized scheme '{}' designated in output url", s),
                }
        }
        DataType::File(file) if file == Path::new("-") => once(async move {
            Ok(FutAsyncWrite(tokio::io::stdout())
                .into_sink()
                .sink_map_err(Error::from)
                .boxed_sink())
        })
        .boxed(),
        DataType::File(file) => {
            let file = file.to_owned();
            once(async move {
                Ok(FutAsyncWrite(tokio::fs::File::create(file).await?)
                    .into_sink()
                    .sink_map_err(Error::from)
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
            "Invalid settings detected: {}\n\nSee stransmit-rs --help for more info",
            e
        );
        exit(1);
    }
}

async fn run() -> Result<(), Error> {
    env_logger::Builder::from_default_env()
        // .format(|buf, record| writeln!(buf, "{} [{}] {}", record.args()))
        .format_timestamp_micros()
        .init();

    let matches = App::new("stransmit-rs")
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
