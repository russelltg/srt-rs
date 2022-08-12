#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

mod errors;

use errors::{SRT_ERRNO, SRT_ERRNO::*};
use os_socketaddr::OsSocketAddr;
use srt_protocol::{
    connection::ConnectionSettings,
    options::{DataRate, KeySize, LiveBandwidthMode, Percent, Sender, SrtVersion, PacketSize},
    settings::KeySettings,
};

use std::{
    cell::RefCell,
    cmp::min,
    collections::BTreeMap,
    ffi::CString,
    fmt::{self, Debug},
    io::{self, Write},
    mem::{replace, size_of, take},
    net::SocketAddr,
    os::{
        raw::{c_char, c_int},
        unix::prelude::AsRawFd,
    },
    pin::Pin,
    ptr::{self, NonNull},
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, RwLock,
    },
    task::Poll,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{
    channel::mpsc,
    future::{self, poll_fn, select_all, Ready, Shared},
    pending, poll, select,
    sink::SinkExt,
    stream::Peekable,
    FutureExt, StreamExt,
};
use lazy_static::lazy_static;
use log::{error, warn};
use srt_tokio::{
    options::{ListenerOptions, Passphrase, SocketOptions, StreamId, Validation},
    SrtListener, SrtSocket,
};
use tokio::{
    io::unix::AsyncFd,
    pin,
    runtime::{self, Runtime},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout, timeout_at},
};

pub type SRTSOCKET = i32;
pub type SYSSOCKET = c_int;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRT_SOCKOPT {
    SRTO_MSS = 0,        // the Maximum Transfer Unit
    SRTO_SNDSYN = 1,     // if sending is blocking
    SRTO_RCVSYN = 2,     // if receiving is blocking
    SRTO_ISN = 3, // Initial Sequence Number (valid only after srt_connect or srt_accept-ed sockets)
    SRTO_FC = 4,  // Flight flag size (window size)
    SRTO_SNDBUF = 5, // maximum buffer in sending queue
    SRTO_RCVBUF = 6, // UDT receiving buffer size
    SRTO_LINGER = 7, // waiting for unsent data when closing
    SRTO_UDP_SNDBUF = 8, // UDP sending buffer size
    SRTO_UDP_RCVBUF = 9, // UDP receiving buffer size
    // (some space left)
    SRTO_RENDEZVOUS = 12,   // rendezvous connection mode
    SRTO_SNDTIMEO = 13,     // send() timeout
    SRTO_RCVTIMEO = 14,     // recv() timeout
    SRTO_REUSEADDR = 15,    // reuse an existing port or create a new one
    SRTO_MAXBW = 16,        // maximum bandwidth (bytes per second) that the connection can use
    SRTO_STATE = 17,        // current socket state, see UDTSTATUS, read only
    SRTO_EVENT = 18,        // current available events associated with the socket
    SRTO_SNDDATA = 19,      // size of data in the sending buffer
    SRTO_RCVDATA = 20,      // size of data available for recv
    SRTO_SENDER = 21, // Sender mode (independent of conn mode), for encryption, tsbpd handshake.
    SRTO_TSBPDMODE = 22, // Enable/Disable TsbPd. Enable -> Tx set origin timestamp, Rx deliver packet at origin time + delay
    SRTO_LATENCY = 23, // NOT RECOMMENDED. SET: to both SRTO_RCVLATENCY and SRTO_PEERLATENCY. GET: same as SRTO_RCVLATENCY.
    SRTO_INPUTBW = 24, // Estimated input stream rate.
    SRTO_OHEADBW, // MaxBW ceiling based on % over input stream rate. Applies when UDT_MAXBW=0 (auto).
    SRTO_PASSPHRASE = 26, // Crypto PBKDF2 Passphrase (must be 10..79 characters, or empty to disable encryption)
    SRTO_PBKEYLEN,        // Crypto key len in bytes {16,24,32} Default: 16 (AES-128)
    SRTO_KMSTATE,         // Key Material exchange status (UDT_SRTKmState)
    SRTO_IPTTL = 29,      // IP Time To Live (passthru for system sockopt IPPROTO_IP/IP_TTL)
    SRTO_IPTOS,           // IP Type of Service (passthru for system sockopt IPPROTO_IP/IP_TOS)
    SRTO_TLPKTDROP = 31,  // Enable receiver pkt drop
    SRTO_SNDDROPDELAY = 32, // Extra delay towards latency for sender TLPKTDROP decision (-1 to off)
    SRTO_NAKREPORT = 33,  // Enable receiver to send periodic NAK reports
    SRTO_VERSION = 34,    // Local SRT Version
    SRTO_PEERVERSION,     // Peer SRT Version (from SRT Handshake)
    SRTO_CONNTIMEO = 36,  // Connect timeout in msec. Caller default: 3000, rendezvous (x 10)
    SRTO_DRIFTTRACER = 37, // Enable or disable drift tracer
    SRTO_MININPUTBW = 38, // Minimum estimate of input stream rate.
    // (some space left)
    SRTO_SNDKMSTATE = 40, // (GET) the current state of the encryption at the peer side
    SRTO_RCVKMSTATE,      // (GET) the current state of the encryption at the agent side
    SRTO_LOSSMAXTTL, // Maximum possible packet reorder tolerance (number of packets to receive after loss to send lossreport)
    SRTO_RCVLATENCY, // TsbPd receiver delay (mSec) to absorb burst of missed packet retransmission
    SRTO_PEERLATENCY, // Minimum value of the TsbPd receiver delay (mSec) for the opposite side (peer)
    SRTO_MINVERSION, // Minimum SRT version needed for the peer (peers with less version will get connection reject)
    SRTO_STREAMID,   // A string set to a socket and passed to the listener's accepted socket
    SRTO_CONGESTION, // Congestion controller type selection
    SRTO_MESSAGEAPI, // In File mode, use message API (portions of data with boundaries)
    SRTO_PAYLOADSIZE, // Maximum payload size sent in one UDP packet (0 if unlimited)
    SRTO_TRANSTYPE = 50, // Transmission type (set of options required for given transmission type)
    SRTO_KMREFRESHRATE, // After sending how many packets the encryption key should be flipped to the new key
    SRTO_KMPREANNOUNCE, // How many packets before key flip the new key is annnounced and after key flip the old one decommissioned
    SRTO_ENFORCEDENCRYPTION, // Connection to be rejected or quickly broken when one side encryption set or bad password
    SRTO_IPV6ONLY,           // IPV6_V6ONLY mode
    SRTO_PEERIDLETIMEO,      // Peer-idle timeout (max time of silence heard from peer) in [ms]
    SRTO_BINDTODEVICE, // Forward the SOL_SOCKET/SO_BINDTODEVICE option on socket (pass packets only from that device)
    // #if ENABLE_EXPERIMENTAL_BONDING
    //    SRTO_GROUPCONNECT,        // Set on a listener to allow group connection
    //    SRTO_GROUPSTABTIMEO,      // Stability timeout (backup groups) in [us]
    //    SRTO_GROUPTYPE,           // Group type to which an accepted socket is about to be added, available in the handshake
    // #endif
    SRTO_PACKETFILTER = 60,   // Add and configure a packet filter
    SRTO_RETRANSMITALGO = 61, // An option to select packet retransmission algorithm

    SRTO_E_SIZE, // Always last element, not a valid option.
}

#[repr(C)]
pub struct SRT_TRACEBSTATS {
    // global measurements
    msTimeStamp: i64,        // time since the UDT entity is started, in milliseconds
    pktSentTotal: i64,       // total number of sent data packets, including retransmissions
    pktRecvTotal: i64,       // total number of received packets
    pktSndLossTotal: c_int,  // total number of lost packets (sender side)
    pktRcvLossTotal: c_int,  // total number of lost packets (receiver side)
    pktRetransTotal: c_int,  // total number of retransmitted packets
    pktSentACKTotal: c_int,  // total number of sent ACK packets
    pktRecvACKTotal: c_int,  // total number of received ACK packets
    pktSentNAKTotal: c_int,  // total number of sent NAK packets
    pktRecvNAKTotal: c_int,  // total number of received NAK packets
    usSndDurationTotal: i64, // total time duration when UDT is sending data (idle time exclusive)
    //>new
    pktSndDropTotal: c_int,      // number of too-late-to-send dropped packets
    pktRcvDropTotal: c_int,      // number of too-late-to play missing packets
    pktRcvUndecryptTotal: c_int, // number of undecrypted packets
    byteSentTotal: u64,          // total number of sent data bytes, including retransmissions
    byteRecvTotal: u64,          // total number of received bytes
    byteRcvLossTotal: u64,       // total number of lost bytes
    byteRetransTotal: u64,       // total number of retransmitted bytes
    byteSndDropTotal: u64,       // number of too-late-to-send dropped bytes
    byteRcvDropTotal: u64, // number of too-late-to play missing bytes (estimate based on average packet size)
    byteRcvUndecryptTotal: u64, // number of undecrypted bytes
    //<

    // local measurements
    pktSent: i64,              // number of sent data packets, including retransmissions
    pktRecv: i64,              // number of received packets
    pktSndLoss: c_int,         // number of lost packets (sender side)
    pktRcvLoss: c_int,         // number of lost packets (receiver side)
    pktRetrans: c_int,         // number of retransmitted packets
    pktRcvRetrans: c_int,      // number of retransmitted packets received
    pktSentACK: c_int,         // number of sent ACK packets
    pktRecvACK: c_int,         // number of received ACK packets
    pktSentNAK: c_int,         // number of sent NAK packets
    pktRecvNAK: c_int,         // number of received NAK packets
    mbpsSendRate: f64,         // sending rate in Mb/s
    mbpsRecvRate: f64,         // receiving rate in Mb/s
    usSndDuration: i64,        // busy sending time (i.e., idle time exclusive)
    pktReorderDistance: c_int, // size of order discrepancy in received sequences
    pktRcvAvgBelatedTime: f64, // average time of packet delay for belated packets (packets with sequence past the ACK)
    pktRcvBelated: i64,        // number of received AND IGNORED packets due to having come too late
    //>new
    pktSndDrop: c_int,      // number of too-late-to-send dropped packets
    pktRcvDrop: c_int,      // number of too-late-to play missing packets
    pktRcvUndecrypt: c_int, // number of undecrypted packets
    byteSent: u64,          // number of sent data bytes, including retransmissions
    byteRecv: u64,          // number of received bytes
    byteRcvLoss: u64,       // number of retransmitted bytes
    byteRetrans: u64,       // number of retransmitted bytes
    byteSndDrop: u64,       // number of too-late-to-send dropped bytes
    byteRcvDrop: u64, // number of too-late-to play missing bytes (estimate based on average packet size)
    byteRcvUndecrypt: u64, // number of undecrypted bytes
    //<

    // instant measurements
    usPktSndPeriod: f64,        // packet sending period, in microseconds
    pktFlowWindow: c_int,       // flow window size, in number of packets
    pktCongestionWindow: c_int, // congestion window size, in number of packets
    pktFlightSize: c_int,       // number of packets on flight
    msRTT: f64,                 // RTT, in milliseconds
    mbpsBandwidth: f64,         // estimated bandwidth, in Mb/s
    byteAvailSndBuf: c_int,     // available UDT sender buffer size
    byteAvailRcvBuf: c_int,     // available UDT receiver buffer size
    //>new
    mbpsMaxBW: f64, // Transmit Bandwidth ceiling (Mbps)
    byteMSS: c_int, // MTU

    pktSndBuf: c_int,       // UnACKed packets in UDT sender
    byteSndBuf: c_int,      // UnACKed bytes in UDT sender
    msSndBuf: c_int,        // UnACKed timespan (msec) of UDT sender
    msSndTsbPdDelay: c_int, // Timestamp-based Packet Delivery Delay

    pktRcvBuf: c_int,       // Undelivered packets in UDT receiver
    byteRcvBuf: c_int,      // Undelivered bytes of UDT receiver
    msRcvBuf: c_int,        // Undelivered timespan (msec) of UDT receiver
    msRcvTsbPdDelay: c_int, // Timestamp-based Packet Delivery Delay

    pktSndFilterExtraTotal: c_int, // number of control packets supplied by packet filter
    pktRcvFilterExtraTotal: c_int, // number of control packets received and not supplied back
    pktRcvFilterSupplyTotal: c_int, // number of packets that the filter supplied extra (e.g. FEC rebuilt)
    pktRcvFilterLossTotal: c_int,   // number of packet loss not coverable by filter

    pktSndFilterExtra: c_int, // number of control packets supplied by packet filter
    pktRcvFilterExtra: c_int, // number of control packets received and not supplied back
    pktRcvFilterSupply: c_int, // number of packets that the filter supplied extra (e.g. FEC rebuilt)
    pktRcvFilterLoss: c_int,   // number of packet loss not coverable by filter
    pktReorderTolerance: c_int, // packet reorder tolerance value
    //<

    // New stats in 1.5.0

    // Total
    pktSentUniqueTotal: i64, // total number of data packets sent by the application
    pktRecvUniqueTotal: i64, // total number of packets to be received by the application
    byteSentUniqueTotal: u64, // total number of data bytes, sent by the application
    byteRecvUniqueTotal: u64, // total number of data bytes to be received by the application

    // Local
    pktSentUnique: i64,  // number of data packets sent by the application
    pktRecvUnique: i64,  // number of packets to be received by the application
    byteSentUnique: u64, // number of data bytes, sent by the application
    byteRecvUnique: u64, // number of data bytes to be received by the application
}

#[repr(C)]
#[repr(C)]
pub struct SRT_MSGCTRL {
    /// Left for future
    flags: c_int,
    /// TTL for a message (millisec), default -1 (no TTL limitation)
    msgttl: c_int,
    /// Whether a message is allowed to supersede partially lost one. Unused in stream and live mode.
    inorder: c_int,
    /// 0:mid pkt, 1(01b):end of frame, 2(11b):complete frame, 3(10b): start of frame
    boundary: c_int,
    /// source time since epoch (usec), 0: use internal time (sender)
    srctime: i64,
    /// sequence number of the first packet in received message (unused for sending)
    pktseq: i32,
    /// message number (output value for both sending and receiving)
    msgno: i32,
    grpdata: *const (),
    grpdata_size: usize,
}

// Safety: the pointers are essentially references
unsafe impl Send for SRT_MSGCTRL {}
unsafe impl Sync for SRT_MSGCTRL {}

#[repr(C)]
pub enum SRT_TRANSTYPE {
    SRTT_LIVE,
    SRTT_FILE,
    SRTT_INVALID,
}

/// system is unstable
pub const LOG_EMERG: c_int = 0;
/// action must be taken immediately
pub const LOG_ALERT: c_int = 1;
/// critical conditions
pub const LOG_CRIT: c_int = 2;
/// error conditions
pub const LOG_ERR: c_int = 3;
/// warning conditions
pub const LOG_WARNING: c_int = 4;
/// normal but significant condition
pub const LOG_NOTICE: c_int = 5;
/// informational
pub const LOG_INFO: c_int = 6;
/// debug-level messages
pub const LOG_DEBUG: c_int = 7;

const SRT_SUCCESS: c_int = 0;
/// Error return code
pub const SRT_ERROR: c_int = -1;

pub const SRT_LIVE_DEF_PLSIZE: c_int = 1316;
pub const SRT_INVALID_SOCK: SRTSOCKET = -1;

// C++11 std::chrono::steady_clock
pub const SRT_SYNC_CLOCK_STDCXX_STEADY: c_int = 0;

// clock_gettime with CLOCK_MONOTONIC
pub const SRT_SYNC_CLOCK_GETTIME_MONOTONIC: c_int = 1;
pub const SRT_SYNC_CLOCK_WINQPC: c_int = 2;
pub const SRT_SYNC_CLOCK_MACH_ABSTIME: c_int = 3;
pub const SRT_SYNC_CLOCK_POSIX_GETTIMEOFDAY: c_int = 4;
pub const SRT_SYNC_CLOCK_AMD64_RDTSC: c_int = 5;
pub const SRT_SYNC_CLOCK_IA32_RDTSC: c_int = 6;
pub const SRT_SYNC_CLOCK_IA64_ITC: c_int = 7;

lazy_static! {
    // xxx: remove
    static ref TOKIO_RUNTIME: Runtime = {
        let rt = runtime::Builder::new_multi_thread().worker_threads(3).enable_all().build().unwrap();

        #[cfg(feature = "console-subscriber")]
        console_subscriber::init();
        rt
    };
    static ref SOCKETS: RwLock<BTreeMap<SRTSOCKET, Arc<Mutex<SocketData>>>> =
        RwLock::new(BTreeMap::new());

    static ref BASE_TIME: Instant = Instant::now();
}

static NEXT_SOCKID: AtomicI32 = AtomicI32::new(1);

#[derive(Clone, Copy, Debug)]
struct ApiOptions {
    snd_syn: bool, // corresponds to SRTO_SNDSYN
    rcv_syn: bool, // corresponds to SRTO_RCVSYN
    listen_cb: Option<srt_listen_callback_fn>,
    listen_cb_opaque: *mut (),
}

// Safety: the pointer to listen_cb_opaque must be threadsafe
unsafe impl Send for ApiOptions {}
unsafe impl Sync for ApiOptions {}

impl Default for ApiOptions {
    fn default() -> Self {
        Self {
            snd_syn: true,
            rcv_syn: true,
            listen_cb: None,
            listen_cb_opaque: ptr::null_mut(),
        }
    }
}

#[derive(Debug)]
enum SocketData {
    Initialized(SocketOptions, Option<StreamId>, ApiOptions),
    ConnectingNonBlocking(Shared<tokio::sync::oneshot::Receiver<()>>, ApiOptions),
    Established(SrtSocket, ApiOptions),
    Listening(
        SrtListener,
        Option<Peekable<mpsc::Receiver<(SRTSOCKET, SocketAddr)>>>,
        JoinHandle<()>,
        ApiOptions,
    ),
    ConnectFailed(io::Error),

    Accepting(Option<KeySettings>),

    InvalidIntermediateState,
    Closed,
}

impl SocketData {
    fn api_opts(&self) -> Option<&ApiOptions> {
        use SocketData::*;
        match self {
            Initialized(_, _, opts)
            | ConnectingNonBlocking(_, opts)
            | Established(_, opts)
            | Listening(_, _, _, opts) => Some(opts),
            _ => None,
        }
    }

    fn sock_opts(&self) -> Option<&SocketOptions> {
        if let SocketData::Initialized(ref opts, _, _) = self {
            Some(opts)
        } else {
            None
        }
    }

    fn conn_settings(&self) -> Option<&ConnectionSettings> {
        if let SocketData::Established(sock, _) = self {
            Some(sock.settings())
        } else {
            None
        }
    }

    fn opts_mut(&mut self) -> (Option<&mut ApiOptions>, Option<&mut SocketOptions>) {
        use SocketData::*;
        match self {
            Initialized(so, _, ai) => (Some(ai), Some(so)),
            ConnectingNonBlocking(_, ai) | Established(_, ai) | Listening(_, _, _, ai) => {
                (Some(ai), None)
            }
            _ => (None, None),
        }
    }
}

fn get_sock(sock: SRTSOCKET) -> Option<Arc<Mutex<SocketData>>> {
    SOCKETS.read().unwrap().get(&sock).cloned()
}

#[no_mangle]
pub extern "C" fn srt_startup() -> c_int {
    lazy_static::initialize(&TOKIO_RUNTIME);
    lazy_static::initialize(&SOCKETS);
    lazy_static::initialize(&BASE_TIME);

    let _ = pretty_env_logger::try_init();
    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_cleanup() -> c_int {
    SOCKETS.write().unwrap().clear();
    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_getversion() -> u32 {
    SrtVersion::CURRENT.to_u32()
}

#[no_mangle]
pub extern "C" fn srt_clock_type() -> c_int {
    // According to Instant's docs, it uses the monotinic clock
    SRT_SYNC_CLOCK_GETTIME_MONOTONIC
}

#[no_mangle]
pub extern "C" fn srt_bind(
    sock: SRTSOCKET,
    name: Option<&libc::sockaddr>,
    namelen: c_int,
) -> c_int {
    let name = match name {
        Some(name) => name,
        None => return set_error_fmt(SRT_EINVPARAM, "Invalid socket address"),
    };
    let name = unsafe {
        OsSocketAddr::from_raw_parts(name as *const libc::sockaddr as *const u8, namelen as usize)
    };
    let name = match name.into_addr() {
        Some(name) => name,
        None => return set_error(SRT_EINVPARAM),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    if let SocketData::Initialized(ref mut b, _, _) = *l {
        b.connect.local = name;
        SRT_SUCCESS
    } else {
        set_error(SRT_ECONNSOCK)
    }
}

#[no_mangle]
pub extern "C" fn srt_listen(sock: SRTSOCKET, _backlog: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    let sd = replace(&mut *l, SocketData::InvalidIntermediateState);
    if let SocketData::Initialized(so, _, initial_opts) = sd {
        let options = match (ListenerOptions { socket: so }.try_validate()) {
            Ok(options) => options,
            Err(e) => return set_error_fmt(SRT_EINVOP, format_args!("Invalid options: {}", e)),
        };
        let ret = TOKIO_RUNTIME.block_on(SrtListener::bind(options));
        let (listener, mut incoming) = match ret {
            Ok(l) => l,
            Err(e) => {
                return set_error_fmt(
                    SRT_EINVOP,
                    format_args!("Failed to listen on socket: {}", e),
                )
            }
        };

        let (mut s, r) = mpsc::channel(1024);
        let sock = sock.clone();
        let task = TOKIO_RUNTIME.spawn(async move {
            let incoming_stream = incoming.incoming();
            while let Some(req) = incoming_stream.next().await {
                let new_sock = insert_socket(SocketData::Accepting(None));

                // get latest opts--callback may be changed at any point
                let opts = {
                    let l = sock.lock().unwrap();
                    *l.api_opts().unwrap()
                };

                let req = req;
                let accept = if let Some(cb) = opts.listen_cb {
                    let streamid_cstr = req
                        .stream_id()
                        .map(|id| CString::new(id.to_string()).unwrap());
                    let streamid_ptr = match &streamid_cstr {
                        Some(cstr) => cstr.as_ptr(),
                        None => ptr::null(),
                    };

                    let mut ret: c_int = 0;

                    let exception_thrown = unsafe {
                        call_callback_wrap_exception(
                            cb,
                            opts.listen_cb_opaque,
                            new_sock,
                            5,
                            OsSocketAddr::from(req.remote()).as_ptr() as *const libc::sockaddr,
                            streamid_ptr,
                            &mut ret,
                        )
                    };

                    exception_thrown == 0 && ret == 0
                } else {
                    true
                };

                if !accept {
                    // connection rejected! try again
                    srt_close(new_sock);
                    continue;
                }

                let new_sock_entry = get_sock(new_sock).expect("socket closed in a weird way?");
                let key_settings = {
                    let mut l = new_sock_entry.lock().unwrap();
                    if let SocketData::Accepting(ref mut key_settings) = *l {
                        key_settings.take()
                    } else {
                        // uhh definitely strange
                        continue;
                    }
                };

                let remote = req.remote();
                let srt_socket = match req.accept(key_settings).await {
                    Ok(sock) => sock,
                    Err(_e) => continue, // TODO: remove from sockets
                };

                {
                    let mut l = new_sock_entry.lock().unwrap();
                    *l = SocketData::Established(srt_socket, opts);
                }

                if s.send((new_sock, remote)).await.is_err() {
                    break;
                }
            }
        });
        *l = SocketData::Listening(listener, Some(r.peekable()), task, initial_opts)
    } else {
        *l = sd;
        return set_error(SRT_ECONNSOCK);
    }

    SRT_SUCCESS
}

#[repr(C)]
// I'm not sure if this lint is pointing out a potential issue or not
// It however does create the right header for cbindgen, so I assume it's alright...
#[allow(clippy::enum_clike_unportable_variant)]
pub enum SRT_EPOLL_OPT {
    SRT_EPOLL_OPT_NONE = 0x0, // fallback

    // Values intended to be the same as in `<sys/epoll.h>`.
    // so that if system values are used by mistake, they should have the same effect
    // This applies to: IN, OUT, ERR and ET.
    /// Ready for 'recv' operation:
    ///
    /// - For stream mode it means that at least 1 byte is available.
    /// In this mode the buffer may extract only a part of the packet,
    /// leaving next data possible for extraction later.
    ///
    /// - For message mode it means that there is at least one packet
    /// available (this may change in future, as it is desired that
    /// one full message should only wake up, not single packet of a
    /// not yet extractable message).
    ///
    /// - For live mode it means that there's at least one packet
    /// ready to play.
    ///
    /// - For listener sockets, this means that there is a new connection
    /// waiting for pickup through the `srt_accept()` call, that is,
    /// the next call to `srt_accept()` will succeed without blocking
    /// (see an alias SRT_EPOLL_ACCEPT below).
    SRT_EPOLL_IN = 0x1,

    /// Ready for 'send' operation.
    ///
    /// - For stream mode it means that there's a free space in the
    /// sender buffer for at least 1 byte of data. The next send
    /// operation will only allow to send as much data as it is free
    /// space in the buffer.
    ///
    /// - For message mode it means that there's a free space for at
    /// least one UDP packet. The edge-triggered mode can be used to
    /// pick up updates as the free space in the sender buffer grows.
    ///
    /// - For live mode it means that there's a free space for at least
    /// one UDP packet. On the other hand, no readiness for OUT usually
    /// means an extraordinary congestion on the link, meaning also that
    /// you should immediately slow down the sending rate or you may get
    /// a connection break soon.
    ///
    /// - For non-blocking sockets used with `srt_connect*` operation,
    /// this flag simply means that the connection was established.
    SRT_EPOLL_OUT = 0x4,

    /// The socket has encountered an error in the last operation
    /// and the next operation on that socket will end up with error.
    /// You can retry the operation, but getting the error from it
    /// is certain, so you may as well close the socket.
    SRT_EPOLL_ERR = 0x8,

    SRT_EPOLL_UPDATE = 0x10,
    SRT_EPOLL_ET = 1 << 31,
}

// To avoid confusion in the internal code, the following
// duplicates are introduced to improve clarity.
pub const SRT_EPOLL_CONNECT: SRT_EPOLL_OPT = SRT_EPOLL_OPT::SRT_EPOLL_OUT;
pub const SRT_EPOLL_ACCEPT: SRT_EPOLL_OPT = SRT_EPOLL_OPT::SRT_EPOLL_IN;

enum SrtEpollEntry {
    Srt(SRTSOCKET, c_int),
    Sys(AsyncFd<SYSSOCKET>, c_int),
}

impl SrtEpollEntry {
    pub(crate) fn id(&self) -> i32 {
        match self {
            SrtEpollEntry::Srt(s, _) => *s,
            SrtEpollEntry::Sys(s, _) => s.as_raw_fd(),
        }
    }
}

struct SrtEpoll {
    socks: Vec<SrtEpollEntry>,
}

lazy_static! {
    static ref EPOLLS: RwLock<BTreeMap<c_int, Arc<Mutex<SrtEpoll>>>> = RwLock::new(BTreeMap::new());
}
static NEXT_EPOLLID: AtomicI32 = AtomicI32::new(1);

fn get_epoll(id: c_int) -> Option<Arc<Mutex<SrtEpoll>>> {
    EPOLLS.read().unwrap().get(&id).cloned()
}

#[no_mangle]
pub extern "C" fn srt_epoll_create() -> c_int {
    let id = NEXT_EPOLLID.fetch_add(1, Ordering::SeqCst) as c_int;
    EPOLLS
        .write()
        .unwrap()
        .entry(id)
        .or_insert_with(|| Arc::new(Mutex::new(SrtEpoll { socks: Vec::new() })));
    id
}

/// # Safety
/// * events must be null or point to a valid combination of `SRT_EPOLL_OPT` flags
#[no_mangle]
pub unsafe extern "C" fn srt_epoll_add_usock(
    eid: c_int,
    sock: SRTSOCKET,
    events: *const c_int,
) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID),
        Some(sock) => sock,
    };

    let flags = if events.is_null() {
        SRT_EPOLL_OPT::SRT_EPOLL_OPT_NONE as i32
    } else {
        events.read()
    };

    if (flags
        & !(SRT_EPOLL_OPT::SRT_EPOLL_IN as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_OUT as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_ERR as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_UPDATE as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_ET as c_int))
        != 0
    {
        // unknown flag
        return set_error(SRT_EINVPARAM);
    }

    let mut l = epoll.lock().unwrap();
    l.socks.push(SrtEpollEntry::Srt(sock, flags));

    SRT_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn srt_epoll_add_ssock(
    eid: c_int,
    s: SYSSOCKET,
    events: *const c_int,
) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID),
        Some(sock) => sock,
    };

    let flags = if events.is_null() {
        SRT_EPOLL_OPT::SRT_EPOLL_OPT_NONE as i32
    } else {
        events.read()
    };

    if (flags
        & !(SRT_EPOLL_OPT::SRT_EPOLL_IN as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_OUT as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_ERR as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_UPDATE as c_int
            | SRT_EPOLL_OPT::SRT_EPOLL_ET as c_int))
        != 0
    {
        // unknown flag
        return set_error(SRT_EINVPARAM);
    }

    let mut l = epoll.lock().unwrap();

    TOKIO_RUNTIME.block_on(async {
        l.socks
            .push(SrtEpollEntry::Sys(AsyncFd::new(s).unwrap(), flags));
    });

    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_epoll_remove_usock(eid: c_int, sock: SRTSOCKET) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID),
        Some(sock) => sock,
    };

    let mut l = epoll.lock().unwrap();
    match l
        .socks
        .iter()
        .position(|s| matches!(s, SrtEpollEntry::Srt(c, _) if *c == sock))
    {
        Some(p) => l.socks.remove(p),
        None => return set_error(SRT_EINVSOCK),
    };

    SRT_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn srt_epoll_update_usock(eid: c_int, u: SRTSOCKET, events: *const c_int) -> c_int {
    if events.is_null() {
        return set_error(SRT_EINVPARAM);
    }
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID),
        Some(sock) => sock,
    };

    let mut l = epoll.lock().unwrap();
    for s in &mut l.socks {
        match s {
            SrtEpollEntry::Srt(sockid, _) if *sockid == u => { *s = SrtEpollEntry::Srt(u, events.read()); return SRT_SUCCESS}
            _ => {}
        }
    }

    set_error(SRT_EINVSOCK)
}

#[no_mangle]
pub extern "C" fn srt_epoll_release(eid: c_int) -> c_int {
    if EPOLLS.write().unwrap().remove(&eid).is_none() {
        return set_error(SRT_EINVPOLLID);
    }
    SRT_SUCCESS
}

#[derive(Eq, PartialEq)]
enum ReadyPendingError {
    Ready,
    Pending,
    Error,
}

impl<T, E: Debug> From<Poll<Result<T, E>>> for ReadyPendingError {
    fn from(s: Poll<Result<T, E>>) -> Self {
        match s {
            Poll::Ready(Ok(_)) => ReadyPendingError::Ready,
            Poll::Ready(Err(e)) => {log::error!("Got poll error: {:?}", e); ReadyPendingError::Error},
            Poll::Pending => ReadyPendingError::Pending,
        }
    }
}

impl<T> From<Poll<Option<T>>> for ReadyPendingError {
    fn from(s: Poll<Option<T>>) -> Self {
        match s {
            Poll::Ready(Some(_)) => ReadyPendingError::Ready,
            Poll::Ready(None) => ReadyPendingError::Error,
            Poll::Pending => ReadyPendingError::Pending,
        }
    }
}

/// # Safety
/// * `(r|w)num` is not null
/// * `(read|write)fds` points to a valid array of `*(r|w)num` elemens
#[no_mangle]
pub unsafe extern "C" fn srt_epoll_wait(
    eid: c_int,
    readfds: *mut SRTSOCKET,
    rnum: *mut c_int,
    writefds: *mut SRTSOCKET,
    wnum: *mut c_int,
    msTimeOut: i64,
    lrfds: *mut SYSSOCKET,
    lrnum: *mut c_int,
    lwfds: *mut SYSSOCKET,
    lwnum: *mut c_int,
) -> c_int {
    let sleep_fut = async {
        if let Ok(to) = msTimeOut.try_into() {
            sleep(Duration::from_millis(to)).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    pin!(sleep_fut);

    // TODO: actually bound check with these
    let rnum_in = if rnum.is_null() { 0 } else { rnum.read() };
    let wnum_in = if wnum.is_null() { 0 } else { wnum.read() };

    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID),
        Some(sock) => sock,
    };

    let mut l = epoll.lock().unwrap();


    TOKIO_RUNTIME.block_on(async {

        let mut written_wfds = 0;
        let mut written_rfds = 0;
        
        let mut written_lwfds = 0;
        let mut written_lrfds = 0;

        // hold onto the join handles, or else the waker is destroyed for ConnectingNonBlocking
        // there may be a better solution to this, idk

        let mut jhs = vec![];

        loop {
            jhs.clear();

            // sleep
            if let Poll::Ready(()) = poll!(&mut sleep_fut) {
                break;
            }

            // poll all the sockets
            // NOTE: don't await in this block, we need to not hold `sock_l` when we return pending() (below in the pending!() call)
            for (idx, epollentry) in l.socks.iter().enumerate() {
                let socket_poll_res: Option<(usize, ReadyPendingError, ReadyPendingError, c_int)> =
                    match epollentry {
                        SrtEpollEntry::Srt(sock, flags) => {
                            let sock = match get_sock(*sock) {
                                Some(sock) => sock,
                                None => continue,
                            };

                            let mut sock_l = sock.lock().unwrap();

                            match &mut *sock_l {
                                SocketData::Established(sock, _opts) => {
                                    let (stream, mut sink) = sock.split_mut();

                                    let ready_recv = poll!(stream.peek()).into();
                                    let ready_send =
                                        poll!(poll_fn(|cx| sink.poll_ready_unpin(cx))).into();

                                    Some((idx, ready_recv, ready_send, *flags))
                                }
                                SocketData::ConnectingNonBlocking(jh, _) => {
                                    let mut jh = jh.clone();
                                    let ready_recv = poll!(&mut jh).into();
                                    jhs.push(jh);
                                    Some((idx, ready_recv, ReadyPendingError::Pending, *flags))
                                }

                                SocketData::Listening(_, i, _, _) => {
                                    if let Some(recv) = i {
                                        let ready_recv = poll!(Pin::new(recv).peek()).into();
                                        Some((idx, ready_recv, ReadyPendingError::Pending, *flags))
                                    } else {
                                        None
                                    }
                                }
                                SocketData::ConnectFailed(_) => Some((
                                    idx,
                                    ReadyPendingError::Error,
                                    ReadyPendingError::Pending,
                                    *flags,
                                )),
                                SocketData::Accepting(_) => todo!(),
                                SocketData::InvalidIntermediateState
                                | SocketData::Closed
                                | SocketData::Initialized(_, _, _) => None,
                            }
                        }
                        SrtEpollEntry::Sys(sock, flags) => {
                            let ready_recv = poll!(poll_fn(|cx|  sock.poll_read_ready(cx))).into();
                            let ready_send = poll!(poll_fn(|cx|  sock.poll_write_ready(cx))).into();

                            Some((idx, ready_recv, ready_send, *flags))
                        }
                    };

                if let Some((idx, read, write, flags)) = socket_poll_res {
                    let out_requested = flags & SRT_EPOLL_OPT::SRT_EPOLL_OUT as c_int != 0;
                    let in_requested = flags & SRT_EPOLL_OPT::SRT_EPOLL_IN as c_int != 0;
                    let err_requested = flags & SRT_EPOLL_OPT::SRT_EPOLL_ERR as c_int != 0;

                    let was_error =
                        read == ReadyPendingError::Error || write == ReadyPendingError::Error;

                    if (in_requested && read == ReadyPendingError::Ready)
                        || (err_requested && was_error)
                    {
                        match &l.socks[idx] {
                            SrtEpollEntry::Srt(fd, _) => {
                                readfds
                                    .offset(written_rfds as isize)
                                    .write(*fd);
                                written_rfds += 1;
                            }
                            SrtEpollEntry::Sys(fd, _) => {
                                lrfds
                                    .offset(written_lrfds as isize)
                                    .write(fd.as_raw_fd());
                                written_lrfds += 1;
                            }
                        }
                    }

                    if (out_requested && write == ReadyPendingError::Ready)
                        || (err_requested && was_error)
                    {
                        match &l.socks[idx] {
                            SrtEpollEntry::Srt(fd, _) => {
                                writefds
                                    .offset(written_wfds as isize)
                                    .write(*fd);
                                written_wfds += 1;
                            }
                            SrtEpollEntry::Sys(fd, _) => {
                               lwfds 
                                    .offset(written_lwfds as isize)
                                    .write(fd.as_raw_fd());
                                written_lwfds += 1;

                            }
                        }
                    }
                }
            }

            // if this loop got anything, then go for it
            // otherwise, return pending
            if written_rfds == 0 && written_wfds == 0 && written_lrfds == 0 && written_lwfds == 0{
                pending!();
                continue;
            } else {
                break;
            }
        }

        if !rnum.is_null() {
            rnum.write(written_rfds as c_int);
        }
        if !wnum.is_null() {
            wnum.write(written_wfds as c_int);
        }

        if !lrnum.is_null() {
            lrnum.write(written_lrfds as c_int);
        }
        if !lwnum.is_null() {
            lwnum.write(written_lwfds as c_int);
        }

        (written_wfds + written_rfds + written_lrfds + written_lwfds) as c_int
    })
}

#[no_mangle]
pub extern "C" fn srt_connect(
    sock: SRTSOCKET,
    name: Option<&libc::sockaddr>,
    namelen: c_int,
) -> c_int {
    let name = match name {
        Some(name) => name,
        None => return set_error_fmt(SRT_EINVPARAM, "Invalid socket address"),
    };
    let name = unsafe {
        OsSocketAddr::from_raw_parts(name as *const libc::sockaddr as *const u8, min(namelen as usize, size_of::<libc::sockaddr_in6>()))
    };
    let name = match name.into_addr() {
        Some(name) => name,
        None => return set_error(SRT_EINVPARAM),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    let sd = replace(&mut *l, SocketData::InvalidIntermediateState);

    if let SocketData::Initialized(so, streamid, options) = sd {
        let sock_clone = sock.clone();
        let sb = SrtSocket::builder().with(so.clone());
        if options.rcv_syn {
            drop(l); // drop lock to avoid holding lock during blocking call

            // blocking mode, wait on oneshot
            let res = TOKIO_RUNTIME
                .block_on(async { sb.call(name, streamid.as_ref().map(|s| s.as_str())).await });

            let mut l = sock_clone.lock().unwrap();
            match res {
                Ok(sock) => *l = SocketData::Established(sock, options),
                Err(e) => {
                    *l = SocketData::Initialized(so, streamid, options);
                    return set_error_fmt(SRT_ENOSERVER, format_args!("Failed to connect: {}", e));
                }
            }
        } else {
            // nonblocking mode

            let (done_s, done_r) = oneshot::channel();
            TOKIO_RUNTIME.spawn(async move {
                let res = sb.call(name, None).await;
                let mut l = sock_clone.lock().unwrap();
                match res {
                    Ok(s) => {
                        done_s.send(()).expect("socket destroyed while connecting");
                        *l = SocketData::Established(s, options);
                        // this may need catching
                    }
                    Err(e) => *l = SocketData::ConnectFailed(e),
                }
            });
            *l = SocketData::ConnectingNonBlocking(done_r.shared(), options);
        }
    } else {
        *l = sd; // restore state
        return set_error(SRT_ECONNSOCK);
    }

    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_accept(
    sock: SRTSOCKET,
    addr: Option<&mut libc::sockaddr>,
    addrlen: Option<&mut c_int>,
) -> SRTSOCKET {
    let addr = match (addr, addrlen) {
        (None, None) | (None, Some(_)) => None,
        (Some(addr), Some(addrlen)) => Some((addr, addrlen)),
        (Some(_), None) => return set_error(SRT_EINVPARAM),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    if let SocketData::Listening(ref _listener, ref mut incoming, ref _jh, opts) = *l {
        let mut incoming = match incoming.take() {
            Some(l) => l,
            None => {
                return set_error_fmt(
                    SRT_EINVOP,
                    "accept can only be called from one thread at a time",
                )
            }
        };

        drop(l); // release mutex so other calls don't block

        TOKIO_RUNTIME.block_on(async {
            let req = if opts.rcv_syn {
                // blocking
                incoming.next().await
            } else {
                // nonblocking--10ms for now but could be shorter potentially
                match timeout(Duration::from_millis(10), incoming.next()).await {
                    Err(_) => return set_error(SRT_EASYNCRCV),
                    Ok(req) => req,
                }
            };

            let (new_sock, remote) = match req {
                Some(req) => req,
                None => return set_error(SRT_ESCLOSED),
            };

            // put listener back
            {
                let mut l = sock.lock().unwrap();
                if let SocketData::Listening(_listener, in_state, _jh, _opts) = &mut *l {
                    *in_state = Some(incoming);
                }
            }

            if let Some((addr, len)) = addr {
                let osa = OsSocketAddr::from(remote);
                *addr = unsafe { *(osa.as_ptr() as *const libc::sockaddr) };
                *len = osa.len() as c_int;
            }

            new_sock
        })
    } else {
        set_error(SRT_ENOLISTEN)
    }
}

fn set_error_fmt(err: SRT_ERRNO, args: impl fmt::Display) -> c_int {
    LAST_ERROR_STR.with(|l| {
        // it's a bit of gymnastics to reuse the buffer, but totally worth it!
        let mut m = l.borrow_mut();
        let mut vec = take(&mut *m).into_bytes_with_nul();
        vec.clear();
        write!(&mut vec, "{}", args).unwrap();
        vec.push(b'\0');
        *m = CString::from_vec_with_nul(vec).unwrap();
    });
    LAST_ERROR.with(|l| *l.borrow_mut() = err);
    SRT_ERROR
}

fn set_error(err: SRT_ERRNO) -> c_int {
    set_error_fmt(err, err)
}

thread_local! {
    pub static LAST_ERROR_STR: RefCell<CString> = RefCell::new(CString::new("(no error set on this thread)").unwrap());
    pub static LAST_ERROR: RefCell<SRT_ERRNO> = RefCell::new(SRT_ERRNO::SRT_SUCCESS);
}

#[no_mangle]
pub extern "C" fn srt_getlasterror(_errno_loc: *mut c_int) -> c_int {
    LAST_ERROR.with(|l| *l.borrow()) as c_int
}

#[no_mangle]
pub extern "C" fn srt_getlasterror_str() -> *const c_char {
    LAST_ERROR_STR.with(|f| f.borrow().as_c_str().as_ptr())
}

#[no_mangle]
pub extern "C" fn srt_send(sock: SRTSOCKET, buf: *const c_char, len: c_int) -> c_int {
    srt_sendmsg2(sock, buf, len, None)
}

#[no_mangle]
pub extern "C" fn srt_sendmsg(
    sock: SRTSOCKET,
    buf: *const c_char,
    len: c_int,
    ttl: c_int,
    inorder: c_int,
) -> c_int {
    let ctrl = SRT_MSGCTRL {
        msgttl: ttl,
        inorder,
        ..srt_msgctrl_default
    };

    srt_sendmsg2(sock, buf, len, Some(&ctrl))
}

/// Returns number of bytes written
#[no_mangle]
pub extern "C" fn srt_sendmsg2(
    sock: SRTSOCKET,
    buf: *const c_char,
    len: c_int,
    _mctrl: Option<&SRT_MSGCTRL>,
) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    match *l {
        SocketData::Established(ref mut sock, _opts) => {
            // TODO: implement blocking mode
            // TODO: use _mctrl
            if sock
                .try_send(
                    Instant::now(),
                    Bytes::copy_from_slice(unsafe {
                        from_raw_parts(buf as *const u8, len as usize)
                    }),
                )
                .is_err()
            {
                return set_error(SRT_ELARGEMSG);
            }
        }
        _ => return set_error(SRT_ENOCONN),
    }

    len
}

/// Returns the number of bytes read
#[no_mangle]
pub extern "C" fn srt_recv(sock: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let bytes = unsafe { from_raw_parts_mut(buf as *mut u8, len as usize) };

    let mut l = sock.lock().unwrap();
    if let SocketData::Established(ref mut sock, opts) = *l {
        TOKIO_RUNTIME.block_on(async {
            let d = if opts.rcv_syn {
                // block
                sock.next().await
            } else {
                // nonblock
                match timeout(Duration::from_millis(10), sock.next()).await {
                    Err(_) => return set_error(SRT_EASYNCRCV),
                    Ok(d) => d,
                }
            };

            let (_, recvd) = match d {
                Some(Ok(d)) => d,
                Some(Err(e)) => return set_error_fmt(SRT_ECONNLOST, e), // TODO: not sure which error exactly here
                None => return set_error(SRT_ECONNLOST),
            };

            if bytes.len() < recvd.len() {
                error!("Receive buffer was not large enough, truncating...");
            }

            let bytes_to_write = min(bytes.len(), recvd.len());
            bytes[..bytes_to_write].copy_from_slice(&recvd[..bytes_to_write]);
            bytes_to_write as c_int
        })
    } else {
        set_error(SRT_ENOCONN)
    }
}

#[no_mangle]
pub extern "C" fn srt_recvmsg(sock: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int {
    srt_recv(sock, buf, len)
}

#[no_mangle]
pub extern "C" fn srt_bstats(
    _sock: SRTSOCKET,
    _perf: &mut SRT_TRACEBSTATS,
    _clear: c_int,
) -> c_int {
    todo!()
}

fn insert_socket(data: SocketData) -> SRTSOCKET {
    let mut sockets = SOCKETS.write().unwrap();
    let new_sockid = NEXT_SOCKID.fetch_add(1, Ordering::SeqCst);
    sockets.insert(new_sockid, Arc::new(Mutex::new(data)));
    new_sockid
}

#[no_mangle]
pub static srt_msgctrl_default: SRT_MSGCTRL = SRT_MSGCTRL {
    flags: 0,
    msgttl: -1, // infinite
    inorder: 0, // false
    boundary: 0,
    srctime: 0,
    pktseq: -1,
    msgno: -1,
    grpdata: ptr::null(),
    grpdata_size: 0,
};

#[no_mangle]
pub extern "C" fn srt_create_socket() -> SRTSOCKET {
    insert_socket(SocketData::Initialized(
        Default::default(),
        None,
        Default::default(),
    ))
}

#[no_mangle]
pub extern "C" fn srt_setloglevel(ll: c_int) {
    let level = match ll {
        LOG_EMERG => log::Level::Error,
        LOG_ALERT => log::Level::Error,
        LOG_CRIT => log::Level::Error,
        LOG_ERR => log::Level::Error,
        LOG_WARNING => log::Level::Warn,
        LOG_NOTICE => log::Level::Info,
        LOG_INFO => log::Level::Info,
        LOG_DEBUG => log::Level::Debug,
        _ => return, // unknown level
    };

    // TODO: finish
    // how does this work???
}

/// # Safety
/// `optval` must point to a structure of the right type depending on `optname`, according to
/// [the option documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
#[no_mangle]
pub unsafe extern "C" fn srt_setsockopt(
    sock: SRTSOCKET,
    _level: c_int, // unused
    optname: SRT_SOCKOPT,
    optval: *const (),
    optlen: c_int,
) -> c_int {
    srt_setsockflag(sock, optname, optval, optlen)
}

/// # Safety
/// If `optval` is non-null, it must point to the correct datastructure
/// as specified by the [options documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
/// Additionally, `optlen` must start as the size of that datastructure
#[no_mangle]
pub unsafe extern "C" fn srt_getsockopt(
    sock: SRTSOCKET,
    _level: c_int,
    optname: SRT_SOCKOPT,
    optval: *mut (),
    optlen: Option<&mut c_int>,
) -> c_int {
    srt_getsockflag(sock, optname, optval, optlen)
}

#[repr(C)]
pub enum SRT_SOCKSTATUS {
    SRTS_INIT = 1,
    SRTS_OPENED,
    SRTS_LISTENING,
    SRTS_CONNECTING,
    SRTS_CONNECTED,
    SRTS_BROKEN,
    SRTS_CLOSING,
    SRTS_CLOSED,
    SRTS_NONEXIST,
}

#[repr(C)]
pub enum SRT_KM_STATE {
    SRT_KM_S_UNSECURED = 0, //No encryption
    SRT_KM_S_SECURING = 1,  //Stream encrypted, exchanging Keying Material
    SRT_KM_S_SECURED = 2,   //Stream encrypted, keying Material exchanged, decrypting ok.
    SRT_KM_S_NOSECRET = 3,  //Stream encrypted and no secret to decrypt Keying Material
    SRT_KM_S_BADSECRET = 4, //Stream encrypted and wrong secret, cannot decrypt Keying Material
}

#[no_mangle]
pub extern "C" fn srt_getsockstate(sock: SRTSOCKET) -> SRT_SOCKSTATUS {
    use SRT_SOCKSTATUS::*;

    let sock = match get_sock(sock) {
        None => return SRTS_NONEXIST,
        Some(sock) => sock,
    };

    let l = sock.lock().unwrap();
    match *l {
        SocketData::Initialized(_, _, _) => SRTS_INIT,
        SocketData::ConnectingNonBlocking(_, _) => SRTS_CONNECTING,
        SocketData::Established(_, _) => SRTS_CONNECTED,
        SocketData::Listening(_, _, _, _) => SRTS_LISTENING,
        SocketData::ConnectFailed(_) => SRTS_BROKEN,
        SocketData::Accepting(_) => SRTS_LISTENING,
        SocketData::InvalidIntermediateState => SRTS_BROKEN,
        SocketData::Closed => SRTS_CLOSED,
    }
}

#[repr(C)]
pub struct SRT_EPOLL_EVENT {
    fd: SRTSOCKET,
    events: c_int,
}

unsafe fn extract_int(val: Option<NonNull<()>>, len: c_int) -> Option<c_int> {
    if let (Some(ptr), 4) = (val, len) {
        return Some(*ptr.cast::<c_int>().as_ref());
    }
    None
}

unsafe fn extract_i64(val: Option<NonNull<()>>, len: c_int) -> Option<i64> {
    if let (Some(ptr), 8) = (val, len) {
        return Some(*ptr.cast::<i64>().as_ref());
    }
    None
}

unsafe fn extract_bool(val: Option<NonNull<()>>, len: c_int) -> Option<bool> {
    match len {
        4 => extract_int(val, len).map(|i| match i {
            0 => false,
            1 => true,
            o => {
                warn!("Warning: bool should be 1 or 0, not {}. Assuming true", o);
                true
            }
        }),
        1 => match *val?.cast::<u8>().as_ref() {
            0 => Some(false),
            1 => Some(true),
            o => {
                warn!("Warning: bool should be 1 or 0, not {}. Assuming true", o);
                Some(true)
            }
        },
        _ => None,
    }
}

unsafe fn extract_str(val: Option<NonNull<()>>, len: c_int) -> Option<String> {
    if let Some(val) = val {
        let slice = from_raw_parts(val.as_ptr() as *const u8, len as usize);
        String::from_utf8(slice.into()).ok()
    } else {
        None
    }
}

/// # Safety
/// `optval` must point to a structure of the right type depending on `optname`, according to
/// [the option documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
#[no_mangle]
pub unsafe extern "C" fn srt_setsockflag(
    sock: SRTSOCKET,
    opt: SRT_SOCKOPT,
    optval: *const (),
    optlen: c_int,
) -> c_int {
    let optval = NonNull::new(optval as *mut ());
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut sock = sock.lock().unwrap();
    use SRT_SOCKOPT::*;

    if let SocketData::Accepting(ref mut params) = *sock {
        match opt {
            SRTO_PASSPHRASE => {
                *params = Some(KeySettings {
                    passphrase: match extract_str(optval, optlen).map(Passphrase::try_from) {
                        Some(Ok(p)) => p,
                        Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
                    },
                    key_size: params
                        .as_ref()
                        .map(|p| p.key_size)
                        .unwrap_or(KeySize::Unspecified),
                })
            }
            SRTO_RCVLATENCY => {
                warn!("Unimplemented! This would require a hook where there currently is none!")
            }
            _ => unimplemented!("{:?}", opt),
        }
        return SRT_SUCCESS;
    }

    if opt == SRTO_STREAMID {
        if let SocketData::Initialized(_, ref mut init, _) = *sock {
            *init = Some(match extract_str(optval, optlen).map(StreamId::try_from) {
                Some(Ok(sid)) => sid,
                Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
            });
            return SRT_SUCCESS;
        }
        return set_error(SRT_ECONNSOCK);
    }

    match (opt, sock.opts_mut()) {
        (SRTO_SENDER, (_, _)) => {}
        (SRTO_RCVSYN, (Some(o), _)) => {
            o.rcv_syn = match extract_bool(optval, optlen) {
                Some(e) => e,
                None => return set_error(SRT_EINVPARAM),
            }
        }
        (SRTO_SNDSYN, (Some(o), _)) => {
            o.snd_syn = match extract_bool(optval, optlen) {
                Some(e) => e,
                None => return set_error(SRT_EINVPARAM),
            }
        }
        (SRTO_CONNTIMEO, (_, Some(o))) => {
            o.connect.timeout =
                Duration::from_millis(match extract_int(optval, optlen).map(u64::try_from) {
                    Some(Ok(to)) => to,
                    Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
                });
        }
        (SRTO_TSBPDMODE, _) => match extract_bool(optval, optlen) {
            Some(true) => {}
            Some(false) => return set_error(SRT_EINVPARAM), // tsbpd=false is not implemented
            None => return set_error(SRT_EINVPARAM),
        },
        (SRTO_PASSPHRASE, (_, Some(o))) => {
            let pwd = extract_str(optval, optlen);
            if let Some("") = pwd.as_deref() {
                o.encryption.passphrase = None;
            } else {
                o.encryption.passphrase = match pwd.map(Passphrase::try_from) {
                    Some(Ok(p)) => Some(p),
                    Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
                };
            }
        }
        (SRTO_RCVLATENCY, (_, Some(o))) => {
            o.receiver.latency =
                Duration::from_millis(match extract_int(optval, optlen).map(u64::try_from) {
                    Some(Ok(o)) => o,
                    Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
                });
        }
        (SRTO_PEERLATENCY, (_, Some(o))) => {
            o.sender.peer_latency =
                Duration::from_millis(match extract_int(optval, optlen).map(u64::try_from) {
                    Some(Ok(o)) => o,
                    Some(Err(_)) | None => return set_error(SRT_EINVPARAM),
                });
        }
        (SRTO_MININPUTBW, (_, Some(o))) => {
            o.sender.bandwidth = LiveBandwidthMode::Estimated {
                expected: match extract_i64(optval, optlen) {
                    Some(i) => DataRate(i as u64),
                    None => return set_error(SRT_EINVPARAM),
                },
                overhead: match o.sender.bandwidth {
                    LiveBandwidthMode::Estimated { overhead, .. } => overhead,
                    _ => Percent(25), // TODO: what should this be
                },
            }
        }
        (SRTO_PAYLOADSIZE, (_, Some(o))) => {
            o.sender.max_payload_size = match extract_int(optval, optlen).map(u64::try_from)  {
                Some(Ok(mps)) => PacketSize(mps),
                _ => return set_error(SRT_EINVPARAM),
            }
        }
        (o, _) => unimplemented!("{:?}", o),
    }
    SRT_SUCCESS
}

/// # Safety
/// If `optval` is non-null, it must point to the correct datastructure
/// as specified by the [options documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
/// Additionally, `optlen` must start as the size of that datastructure
#[no_mangle]
pub unsafe extern "C" fn srt_getsockflag(
    sock: SRTSOCKET,
    opt: SRT_SOCKOPT,
    optval: *mut (),
    optlen: Option<&mut c_int>,
) -> c_int {
    let optval = NonNull::new(optval);
    let (optval, optlen) = match (optval, optlen) {
        (Some(optval), Some(optlen)) => (optval, optlen),
        _ => return set_error(SRT_EINVPARAM),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let l = sock.lock().unwrap();

    enum Val<'a> {
        Bool(bool),
        Int(c_int),
        Int64(i64),
        Str(&'a str),
    }
    use LiveBandwidthMode::*;
    use Val::*;
    use SRT_SOCKOPT::*;

    let val = if opt == SRTO_STREAMID {
        match &*l {
            SocketData::Initialized(_, sid, _) => {
                Str(sid.as_ref().map(|s| s.as_str()).unwrap_or(""))
            }
            SocketData::Established(sock, _) => {
                Str(sock.settings().stream_id.as_deref().unwrap_or(""))
            }
            _ => return set_error(SRT_EBOUNDSOCK),
        }
    } else {
        match (opt, l.api_opts(), l.sock_opts(), l.conn_settings()) {
            (SRTO_RCVSYN, Some(opts), _, _) => Bool(opts.rcv_syn),
            (SRTO_SNDSYN, Some(opts), _, _) => Bool(opts.snd_syn),
            (SRTO_CONNTIMEO, _, Some(opts), _) => Int(opts.connect.timeout.as_millis() as c_int),
            (SRTO_RCVLATENCY, _, Some(opts), _) => Int(opts.receiver.latency.as_millis() as c_int),
            (SRTO_RCVLATENCY, _, _, Some(cs)) => Int(cs.recv_tsbpd_latency.as_millis() as c_int),
            (SRTO_PEERLATENCY, _, Some(opts), _) => {
                Int(opts.sender.peer_latency.as_millis() as c_int)
            }
            (SRTO_PEERLATENCY, _, _, Some(cs)) => Int(cs.send_tsbpd_latency.as_millis() as c_int),
            (
                SRTO_MININPUTBW,
                _,
                Some(SocketOptions {
                    sender: Sender { bandwidth, .. },
                    ..
                }),
                _,
            )
            | (SRTO_MININPUTBW, _, _, Some(ConnectionSettings { bandwidth, .. })) => {
                Int64(match bandwidth {
                    Max(rate) | Input { rate, .. } | Estimated { expected: rate, .. } => {
                        rate.0 as i64
                    }
                    Unlimited => 0,
                })
            }
            _ => unimplemented!("{:?} {:?}", opt, *l),
        }
    };

    match val {
        Bool(b) => {
            if *optlen != size_of::<c_int>() as c_int {
                return set_error(SRT_EINVPARAM);
            }
            *optval.cast::<c_int>().as_mut() = if b { 1 } else { 0 };
        }
        Int(i) => {
            if *optlen < size_of::<c_int>() as c_int {
                return set_error(SRT_EINVPARAM);
            }
            *optlen = size_of::<c_int>() as c_int;
            *optval.cast::<c_int>().as_mut() = i;
        }
        Int64(i) => {
            if *optlen < size_of::<i64>() as c_int {
                return set_error(SRT_EINVPARAM);
            }
            *optlen = size_of::<i64>() as c_int;
            *optval.cast::<i64>().as_mut() = i;
        }
        Str(str) => {
            if *optlen < (str.as_bytes().len() + 1) as c_int {
                return set_error(SRT_EINVPARAM);
            }
            let optval = from_raw_parts_mut(optval.cast::<u8>().as_mut(), *optlen as usize);
            optval[..str.as_bytes().len()].copy_from_slice(str.as_bytes());
            optval[str.as_bytes().len()] = 0; // null terminator
            *optlen = str.as_bytes().len() as c_int;
        }
    }
    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_getsockname(
    _sock: SRTSOCKET,
    _name: *mut libc::sockaddr,
    _namelen: *mut c_int,
) -> c_int {
    todo!()
}

#[no_mangle]
pub extern "C" fn srt_getpeername(
    _sock: SRTSOCKET,
    _name: *mut libc::sockaddr,
    _namelen: *mut c_int,
) -> c_int {
    todo!()
}

type srt_listen_callback_fn = extern "C" fn(
    opaq: *mut (),
    ns: SRTSOCKET,
    c_int,
    peeraddr: *const libc::sockaddr,
    streamid: *const c_char,
) -> c_int;

/// # Safety
/// - `hook_fn` must contain a function pointer of the right signature
/// - `hook_fn` must be callable from another thread
/// - `hook_opaque` must live as long as the socket and be passable between threads
#[no_mangle]
pub unsafe extern "C" fn srt_listen_callback(
    sock: SRTSOCKET,
    hook_fn: srt_listen_callback_fn,
    hook_opaque: *mut (),
) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };
    let mut l = sock.lock().unwrap();

    if let (Some(o), _) = l.opts_mut() {
        o.listen_cb = Some(hook_fn);
        o.listen_cb_opaque = hook_opaque;
        SRT_SUCCESS
    } else {
        set_error(SRT_ENOCONN) // TODO: which error here?
    }
}

#[no_mangle]
pub extern "C" fn srt_time_now() -> i64 {
    (Instant::now() - *BASE_TIME).as_micros().try_into().expect("did not expect program to run for 2^63 us")
}

extern "C" {
    fn call_callback_wrap_exception(
        func: srt_listen_callback_fn,
        opaq: *mut (),
        ns: SRTSOCKET,
        hsversion: c_int,
        peeraddr: *const libc::sockaddr,
        streamid: *const c_char,
        ret: *mut c_int,
    ) -> c_int;
}

#[no_mangle]
pub extern "C" fn srt_close(socknum: SRTSOCKET) -> c_int {
    let sock = match get_sock(socknum) {
        None => return set_error(SRT_EINVSOCK),
        Some(sock) => sock,
    };

    let mut retcode = SRT_SUCCESS;

    let mut l = sock.lock().unwrap();
    match &mut *l {
        SocketData::Established(ref mut s, _) => {
            let res = TOKIO_RUNTIME.block_on(async move { s.close_and_finish().await });
            if let Err(e) = res {
                retcode = set_error_fmt(SRT_EINVOP, format_args!("Failed to close socket: {}", e));
            }
            *l = SocketData::Closed
        }
        SocketData::Listening(ref mut listener, _, jh, _) => {
            TOKIO_RUNTIME.block_on(async {
                listener.close().await;
                jh.await.unwrap();
            });
            *l = SocketData::Closed;
        }
        _ => (),
    }

    let mut sockets = SOCKETS.write().unwrap();
    sockets.remove(&socknum);

    retcode
}
