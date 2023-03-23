use std::{
    borrow::Cow,
    convert::{TryFrom, TryInto},
    net::{AddrParseError, IpAddr},
    str::FromStr,
    time::Duration,
};

use regex::Regex;
use thiserror::Error;
use url::{Host, ParseError, Url};

use crate::options::*;

/// see https://github.com/Haivision/srt/blob/master/docs/apps/srt-live-transmit.md#medium-srt
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrtUri(BindOptions);

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SrtUriError {
    #[error("{0}")]
    InvalidOptions(#[from] OptionsError),
    #[error("{0}")]
    InvalidUrl(#[from] ParseError),
    #[error("Invalid adapter: {0}")]
    InvalidAdapter(#[from] AddrParseError),
    #[error("Invalid mode: {0}")]
    InvalidMode(String),
    #[error("Invalid parameter: {0}={1}, expected positive integer")]
    InvalidIntParameter(&'static str, String),
    #[error("Unimplemented parameter: {0}")]
    UnimplementedParameter(&'static str),
}

pub fn url_parse(s: &str, mode_listener: bool) -> Result<Url, ParseError> {
    let re = Regex::new(r"([a-z]{3})://:([0-9]*)\??(.*)").unwrap();
    if re.is_match(s) {
        let caps = re.captures(s).unwrap();
        let protocol = caps.get(1).map_or("", |m| m.as_str());
        let port = caps.get(2).map_or("", |m| m.as_str());
        let options = caps.get(3).map_or("", |m| m.as_str());
        let listener = if mode_listener { "mode=listener&" } else { "" };
        Url::parse(&format!(
            "{}://0.0.0.0:{}?{}{}",
            protocol, port, listener, options
        ))
    } else {
        Url::parse(s)
    }
}

impl TryFrom<Url> for SrtUri {
    type Error = SrtUriError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let (mode, adapter, stream_id, mut socket) = Self::parse_query_pairs(&url)?;
        let host = Self::parse_host(&url);
        let port = url.port();

        use SrtUrlMode::*;
        match (mode, host, port, adapter) {
            (Unspecified, None, Some(port), None) => {
                Ok(SrtUri(ListenerOptions::with(port, socket)?.into()))
            }
            (Unspecified, None, Some(port), Some(host)) // DEPRECATED
            | (Listener, Some(host), Some(port), None)
            | (Listener, Some(_), Some(port), Some(host)) => Ok(SrtUri(
                ListenerOptions::with(SocketAddress { host, port }, socket)?.into(),
            )),
            (Unspecified, Some(host), Some(port), adapter @ None)
            | (Caller, Some(host), Some(port), adapter) => {
                if let Some(adapter) = adapter {
                    let ip = adapter.try_into().unwrap();
                    socket.connect.local.set_ip(ip);
                }
                let remote = SocketAddress { host, port };
                let stream_id = stream_id.as_ref().map(|s| s.as_ref());
                Ok(SrtUri(
                    CallerOptions::with(remote, stream_id, socket)?.into(),
                ))
            }
            (Unspecified, Some(host), Some(port), adapter @ Some(_))
            | (Rendezvous, Some(host), Some(port), adapter) => {
                let remote = SocketAddress { host, port };
                if let Some(adapter) = adapter {
                    let ip = adapter.try_into().unwrap();
                    socket.connect.local.set_ip(ip);
                }

                if socket.connect.local.port() == 0 {
                    socket.connect.local.set_port(port);
                }
                Ok(SrtUri(RendezvousOptions::with(remote, socket)?.into()))
            }
            (Caller, Some(_), None, _)
            | (Rendezvous, Some(_), None, _)
            | (Unspecified, None, None, _)
            | (Unspecified, Some(_), None, _)
            | (Listener, None, _, _)
            | (Listener, Some(_), None, _)
            | (Caller, None, _, _)
            | (Rendezvous, None, _, _) => {
                unimplemented!();
            }
        }
    }
}

impl FromStr for SrtUri {
    type Err = SrtUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        url_parse(s, true)?.try_into()
    }
}

enum SrtUrlMode {
    Unspecified,
    Listener,
    Caller,
    Rendezvous,
}

type QueryPairs<'a> = (
    SrtUrlMode,
    Option<SocketHost>,
    Option<Cow<'a, str>>,
    SocketOptions,
);

impl SrtUri {
    fn parse_query_pairs(url: &Url) -> Result<QueryPairs, SrtUriError> {
        use SrtUriError::*;

        let mut mode = SrtUrlMode::Unspecified;
        let mut adapter: Option<SocketHost> = None;
        let mut stream_id = None;
        let mut socket = SocketOptions::default();

        let mut inputbw = None;
        let mut maxbw = None;
        let mut mininputbw = None;
        let mut oheadbw = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "mode" => {
                    mode = match value.as_ref() {
                        "listener" => SrtUrlMode::Listener,
                        "caller" => SrtUrlMode::Caller,
                        "rendezvous" => SrtUrlMode::Rendezvous,
                        value => return Err(InvalidMode(value.to_string())),
                    };
                }
                "adapter" => {
                    adapter = Some(
                        IpAddr::from_str(value.as_ref())
                            .map_err(InvalidAdapter)?
                            .into(),
                    );
                }
                "port" => {
                    let value = u16::try_from(Self::parse_int_param("port", value)?)
                        .map_err(|e| SrtUriError::InvalidIntParameter("port", e.to_string()))?;
                    socket.connect.local.set_port(value);
                }
                "conntimeo" => {
                    let value = Self::parse_int_param("conntimeo", value)?;
                    socket.connect.timeout = Duration::from_millis(value);
                }
                "drifttracer" => unimplemented!(),
                "enforcedencryption" => unimplemented!(),
                "fc" => {
                    let value = Self::parse_int_param("fc", value)?;
                    socket.sender.flow_control_window_size = PacketCount(value);
                }
                "groupconnect" => return Err(UnimplementedParameter("groupconnect")),
                "groupstabtimeo" => return Err(UnimplementedParameter("groupstabtimeo")),
                "inputbw" => {
                    let value = Self::parse_int_param("inputbw", value)?;
                    if value > 0 {
                        inputbw = Some(DataRate(value));
                    }
                }
                "iptos" => unimplemented!(),
                "ipttl" => {
                    let value = Self::parse_int_param("ipttl", value)?;
                    if value > 255 {
                        return Err(SrtUriError::InvalidIntParameter("ipttl", value.to_string()));
                    }
                    socket.connect.ip_ttl = value as u8;
                }
                "ipv6only" => unimplemented!(),
                "kmpreannounce" => {
                    let value = Self::parse_int_param("kmpreannounce", value)?;
                    socket.encryption.km_refresh.period = PacketCount(value);
                }
                "kmrefreshrate" => {
                    let value = Self::parse_int_param("kmrefreshrate", value)?;
                    socket.encryption.km_refresh.pre_announcement_period = PacketCount(value);
                }
                "latency" => {
                    let value = Self::parse_int_param("latency", value)?;
                    let latency = Duration::from_millis(value);
                    socket.sender.peer_latency = latency;
                    socket.receiver.latency = latency;
                }
                "linger" => {
                    let value = Self::parse_int_param("linger", value)?;
                    socket.connect.linger = Some(Duration::from_millis(value));
                }
                "lossmaxttl" => {
                    let value = Self::parse_int_param("lossmaxttl", value)?;
                    socket.receiver.reorder_tolerance_max = PacketCount(value);
                }
                "maxbw" => {
                    let value = Self::parse_int_param("maxbw", value)?;
                    if value > 0 {
                        maxbw = Some(DataRate(value));
                    }
                }
                "mininputbw" => {
                    let value = Self::parse_int_param("mininputbw", value)?;
                    if value > 0 {
                        mininputbw = Some(DataRate(value));
                    }
                }
                "messageapi" => return Err(UnimplementedParameter("messageapi")),
                "minversion" => {
                    let digits: Result<Vec<_>, _> =
                        value.as_ref().split('.').map(u8::from_str).collect();
                    match digits {
                        Err(_) => {
                            return Err(SrtUriError::InvalidIntParameter(
                                "minversion",
                                value.to_string(),
                            ))
                        }
                        Ok(digits) if digits.len() != 3 => {
                            return Err(SrtUriError::InvalidIntParameter(
                                "minversion",
                                value.to_string(),
                            ))
                        }
                        Ok(digits) => {
                            socket.connect.min_version =
                                SrtVersion::new(digits[0], digits[1], digits[2])
                        }
                    }
                }
                "mss" => {
                    let value = Self::parse_int_param("mss", value)?;
                    socket.session.max_segment_size = PacketSize(value);
                }
                "nakreport" => unimplemented!(),
                "oheadbw" => {
                    let value = Self::parse_int_param("oheadbw", value)?;
                    if value > 5 {
                        oheadbw = Some(Percent(value));
                    }
                }
                "packetfilter" => return Err(UnimplementedParameter("packetfilter")),
                "passphrase" => {
                    socket.encryption.passphrase = Some(value.to_string().try_into()?);
                }
                "payloadsize" => {
                    let value = Self::parse_int_param("payloadsize", value)?;
                    socket.sender.max_payload_size = PacketSize(value);
                }
                "pbkeylen" => {
                    let value = u16::try_from(Self::parse_int_param("pbkeylen", value)?)
                        .map_err(|e| InvalidIntParameter("pbkeylen", e.to_string()))?;
                    socket.encryption.key_size = value.try_into()?;
                }
                "peeridletimeo" => {
                    let value = Self::parse_int_param("peeridletimeo", value)?;
                    socket.session.peer_idle_timeout = Duration::from_millis(value);
                }
                "peerlatency" => {
                    let value = Self::parse_int_param("peerlatency", value)?;
                    socket.sender.peer_latency = Duration::from_millis(value);
                }
                "rcvbuf" => {
                    let value = Self::parse_int_param("rcvbuf", value)?;
                    socket.receiver.buffer_size = ByteCount(value);
                }
                "rcvlatency" => {
                    let value = Self::parse_int_param("rcvlatency", value)?;
                    socket.receiver.latency = Duration::from_millis(value);
                }
                "retransmitalgo" => unimplemented!(),
                "sndbuf" => {
                    let value = Self::parse_int_param("sndbuf", value)?;
                    socket.sender.buffer_size = ByteCount(value);
                }
                "snddropdelay" => {
                    let value = Self::parse_int_param("snddropdelay", value)?;
                    socket.sender.drop_delay = Duration::from_millis(value);
                }
                "streamid" => {
                    stream_id = Some(value);
                }
                "tlpktdrop" => unimplemented!(),
                "transtype" => return Err(UnimplementedParameter("transtype")),
                "tsbpdmode" => return Err(UnimplementedParameter("tsbpdmode")),
                _ => {}
            }
        }

        socket.sender.bandwidth = match (maxbw, inputbw, oheadbw, mininputbw) {
            (Some(rate), None, _, _) => LiveBandwidthMode::Max(rate),
            (None, Some(rate), overhead, _) => LiveBandwidthMode::Input {
                rate,
                overhead: overhead.unwrap_or(Percent(5)),
            },
            (None, None, overhead, Some(expected)) => LiveBandwidthMode::Estimated {
                expected,
                overhead: overhead.unwrap_or(Percent(5)),
            },
            _ => LiveBandwidthMode::Unlimited,
        };

        Ok((mode, adapter, stream_id, socket))
    }

    fn parse_host(url: &Url) -> Option<SocketHost> {
        let host = match url.host() {
            Some(Host::Domain(domain)) => Some(match IpAddr::from_str(domain) {
                Ok(IpAddr::V4(ip)) => Host::Ipv4(ip),
                Ok(IpAddr::V6(ip)) => Host::Ipv6(ip),
                Err(_) => Host::Domain(domain),
            }),
            host => host,
        };

        let host: Option<SocketHost> = match host {
            Some(Host::Domain("")) | None => None,
            Some(Host::Ipv4(ip)) => Some(ip.into()),
            Some(Host::Ipv6(ip)) => Some(ip.into()),
            Some(Host::Domain(domain)) => Some(SocketHost::Domain(domain.to_string())),
        };
        host
    }

    fn parse_int_param(key: &'static str, value: Cow<str>) -> Result<u64, SrtUriError> {
        match value.as_ref().parse() {
            Ok(0) | Err(_) => Err(SrtUriError::InvalidIntParameter(key, value.to_string())),
            Ok(n) => Ok(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    #[test]
    fn parse_listen() {
        // Listener mode: if you leave the host part empty (adapter may be specified)
        assert_eq!(
            "srt://:1234".parse(),
            Ok(SrtUri(ListenerOptions::new(1234).unwrap().into()))
        );
        assert_eq!(
            "srt://:1234?adapter=127.0.0.1".parse(),
            Ok(SrtUri(
                ListenerOptions::new("127.0.0.1:1234").unwrap().into()
            ))
        );
        assert_eq!(
            "srt://10.10.10.100:5001?mode=listener".parse(),
            Ok(SrtUri(
                ListenerOptions::new("10.10.10.100:5001").unwrap().into()
            ))
        );
    }

    #[test]
    fn parse_call() {
        // Caller mode: if you specify host part, but not adapter parameter
        assert_eq!(
            "srt://10.1.0.1:1234".parse(),
            Ok(SrtUri(
                CallerOptions::new("10.1.0.1:1234", None).unwrap().into()
            ))
        );
        assert_eq!(
            "srt://10.1.0.1:5001?adapter=127.0.0.1&port=4001&mode=caller".parse(),
            Ok(SrtUri(
                CallerOptions::new("10.1.0.1:5001", None)
                    .unwrap()
                    .set(|o| o.socket.connect.local =
                        SocketAddr::from_str("127.0.0.1:4001").unwrap())
                    .unwrap()
                    .into()
            ))
        );
    }

    #[test]
    fn parse_rendezvous() {
        // Rendezvous mode: if you specify host AND adapter parameter
        assert_eq!(
            "srt://10.1.0.1:1234?adapter=127.0.0.1".parse(),
            Ok(SrtUri(
                RendezvousOptions::new("10.1.0.1:1234")
                    .unwrap()
                    .set(|o| o.socket.connect.local = "127.0.0.1:1234".parse().unwrap())
                    .unwrap()
                    .into()
            ))
        );
        assert_eq!(
            "srt://10.1.0.1:5001?mode=rendezvous".parse(),
            Ok(SrtUri(
                RendezvousOptions::new("10.1.0.1:5001")
                    .unwrap()
                    .set(|o| o.socket.connect.local = "0.0.0.0:5001".parse().unwrap())
                    .unwrap()
                    .into()
            ))
        );
        assert_eq!(
            "srt://10.1.0.1:5001?port=4001&adapter=127.0.0.1".parse(),
            Ok(SrtUri(
                RendezvousOptions::new("10.1.0.1:5001")
                    .unwrap()
                    .set(|o| o.socket.connect.local = "127.0.0.1:4001".parse().unwrap())
                    .unwrap()
                    .into()
            ))
        );
    }

    #[test]
    fn parse_parameters() {
        let mut socket = SocketOptions::default();
        socket.connect.timeout = Duration::from_millis(10_000);
        socket.sender.flow_control_window_size = PacketCount(50_000);
        socket.connect.ip_ttl = 32;
        socket.encryption.km_refresh.period = PacketCount(33000);
        socket.encryption.km_refresh.pre_announcement_period = PacketCount(11000);
        socket.sender.peer_latency = Duration::from_millis(42);
        socket.receiver.latency = Duration::from_millis(42);
        socket.connect.linger = Some(Duration::from_millis(128));
        socket.receiver.reorder_tolerance_max = PacketCount(256);
        socket.session.max_segment_size = PacketSize(1300);
        socket.encryption.passphrase = "passphrase1234".try_into().ok();
        socket.sender.max_payload_size = PacketSize(1234);
        socket.encryption.key_size = KeySize::AES256;
        socket.session.peer_idle_timeout = Duration::from_millis(4242);
        socket.receiver.buffer_size = ByteCount(22_000_000);
        socket.sender.buffer_size = ByteCount(23_000_000);
        socket.sender.drop_delay = Duration::from_millis(84);

        assert_eq!(
            SrtUri::from_str("srt://10.1.1.1:1234?conntimeo=10000&fc=50000&ipttl=32&kmpreannounce=33000&kmrefreshrate=11000&latency=42&linger=128&lossmaxttl=256&mss=1300&passphrase=passphrase1234&payloadsize=1234&pbkeylen=32&peeridletimeo=4242&rcvbuf=22000000&sndbuf=23000000&snddropdelay=84&streamid=TheStreamID"),
            Ok(SrtUri(CallerOptions::with("10.1.1.1:1234", Some("TheStreamID"), socket).unwrap().into()))
        );
    }

    #[test]
    fn parse_bandwidth() {
        let mut socket = SocketOptions::default();
        socket.sender.bandwidth = LiveBandwidthMode::Max(DataRate(10_000_000));

        assert_eq!(
            "srt://:1234?maxbw=10000000".parse(),
            Ok(SrtUri(ListenerOptions::with(1234, socket).unwrap().into()))
        );

        let mut socket = SocketOptions::default();
        socket.sender.bandwidth = LiveBandwidthMode::Input {
            rate: DataRate(20_000_000),
            overhead: Percent(5),
        };
        assert_eq!(
            "srt://:1234?inputbw=20000000".parse(),
            Ok(SrtUri(ListenerOptions::with(1234, socket).unwrap().into()))
        );

        let mut socket = SocketOptions::default();
        socket.sender.bandwidth = LiveBandwidthMode::Input {
            rate: DataRate(20_000_000),
            overhead: Percent(10),
        };
        assert_eq!(
            "srt://:1234?inputbw=20000000&oheadbw=10".parse(),
            Ok(SrtUri(ListenerOptions::with(1234, socket).unwrap().into()))
        );

        let mut socket = SocketOptions::default();
        socket.sender.bandwidth = LiveBandwidthMode::Estimated {
            expected: DataRate(30_000_000),
            overhead: Percent(5),
        };
        assert_eq!(
            "srt://:1234?mininputbw=30000000".parse(),
            Ok(SrtUri(ListenerOptions::with(1234, socket).unwrap().into()))
        );

        let mut socket = SocketOptions::default();
        socket.sender.bandwidth = LiveBandwidthMode::Estimated {
            expected: DataRate(30_000_000),
            overhead: Percent(40),
        };
        assert_eq!(
            "srt://:1234?mininputbw=30000000&oheadbw=40".parse(),
            Ok(SrtUri(ListenerOptions::with(1234, socket).unwrap().into()))
        );
    }
}
