#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::{
    cell::RefCell,
    cmp::min,
    collections::BTreeMap,
    ffi::CString,
    intrinsics::transmute,
    io,
    mem::{replace, size_of},
    net::SocketAddr,
    os::raw::{c_char, c_int},
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{sink::SinkExt, AsyncWriteExt, StreamExt};
use lazy_static::lazy_static;
use libc::{sockaddr_in, sockaddr_in6, AF_INET};
use log::{error, warn};
use srt_tokio::{
    options::{ListenerOptions, SocketOptions, Validation},
    SrtListener, SrtSocket,
};
use tokio::{runtime::Runtime, task::JoinHandle, time::timeout};

pub type SRTSOCKET = i32;

#[repr(C)]
#[derive(Debug)]
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
    flags: c_int,
    msgttl: c_int,
    inorder: c_int,
    boundary: c_int,
    srctime: i64,
    pktseq: i32,
    msgno: i32,
    grpdata: *mut (),
    grpdata_size: usize,
}

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

/// Error return code
pub const SRT_ERROR: c_int = -1;

lazy_static! {
    static ref TOKIO_RUNTIME: Runtime = Runtime::new().unwrap();
    static ref SOCKETS: RwLock<BTreeMap<SRTSOCKET, Arc<Mutex<SocketData>>>> =
        RwLock::new(BTreeMap::new());
}

static NEXT_SOCKID: AtomicI32 = AtomicI32::new(1);

#[derive(Clone, Copy)]
struct ApiOptions {
    snd_syn: bool, // corresponds to SRTO_SNDSYN
    rcv_syn: bool, // corresponds to SRTO_RCVSYN
}

impl Default for ApiOptions {
    fn default() -> Self {
        Self {
            snd_syn: true,
            rcv_syn: true,
        }
    }
}

enum SocketData {
    Initialized(SocketOptions, ApiOptions),
    ConnectingNonBlocking(JoinHandle<()>, ApiOptions),
    Established(SrtSocket, ApiOptions),
    Listening(SrtListener, ApiOptions),
    ConnectFailed(io::Error),

    InvalidIntermediateState,
}

fn get_sock(sock: SRTSOCKET) -> Option<Arc<Mutex<SocketData>>> {
    SOCKETS.read().unwrap().get(&sock).cloned()
}

fn sockaddr_from_c(addr: &libc::sockaddr, len: c_int) -> Option<SocketAddr> {
    let len = usize::try_from(len).unwrap();

    if addr.sa_family as c_int != AF_INET {
        return None;
    }

    if len == size_of::<sockaddr_in>() {
        let sa_in: &sockaddr_in = unsafe { transmute(addr) };
        Some(
            (
                sa_in.sin_addr.s_addr.to_ne_bytes(),
                u16::from_ne_bytes(sa_in.sin_port.to_be_bytes()),
            )
                .into(),
        )
    } else if len == size_of::<sockaddr_in6>() {
        let sa_in: &sockaddr_in6 = unsafe { transmute(addr) };
        Some(
            (
                sa_in.sin6_addr.s6_addr,
                u16::from_ne_bytes(sa_in.sin6_port.to_be_bytes()),
            )
                .into(),
        )
    } else {
        None
    }
}

#[no_mangle]
pub extern "C" fn srt_startup() -> c_int {
    lazy_static::initialize(&TOKIO_RUNTIME);
    0
}

#[no_mangle]
pub extern "C" fn srt_cleanup() -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn srt_bind(sock: SRTSOCKET, name: &libc::sockaddr, namelen: c_int) -> c_int {
    let sa = match sockaddr_from_c(name, namelen) {
        None => return set_error("Invalid socket address"),
        Some(sa) => sa,
    };

    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    if let SocketData::Initialized(ref mut b, _) = *l {
        b.connect.local = sa;
        0
    } else {
        set_error("Socket already connecting or listened, cannot bind anymore")
    }
}

#[no_mangle]
pub extern "C" fn srt_listen(sock: SRTSOCKET, _backlog: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    let sd = replace(&mut *l, SocketData::InvalidIntermediateState);
    if let SocketData::Initialized(so, opts) = sd {
        let options = match (ListenerOptions { socket: so }.try_validate()) {
            Ok(options) => options,
            Err(e) => return set_error(&format!("Invalid options: {}", e)),
        };
        let ret = TOKIO_RUNTIME.block_on(SrtListener::bind(options));
        *l = SocketData::Listening(
            match ret {
                Ok(l) => l,
                Err(e) => return set_error(&format!("Failed to listen on socket: {}", e)),
            },
            opts,
        )
    } else {
        *l = sd;
        return set_error("Cannot listen, listen or connect has already been called");
    }

    0
}

#[no_mangle]
pub extern "C" fn srt_connect(sock: SRTSOCKET, name: &libc::sockaddr, namelen: c_int) -> c_int {
    let sa = match sockaddr_from_c(name, namelen) {
        None => return set_error("Invalid socket address"),
        Some(sa) => sa,
    };

    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    let sd = replace(&mut *l, SocketData::InvalidIntermediateState);
    if let SocketData::Initialized(so, options) = sd {
        let sb = SrtSocket::builder().with(so);
        if options.rcv_syn {
            // blocking mode, wait on oneshot
            let res = TOKIO_RUNTIME.block_on(async move { sb.call(sa, None).await });
            match res {
                Ok(sock) => *l = SocketData::Established(sock, options),
                Err(e) => return set_error(&format!("Failed to connect: {}", e)),
            }
        } else {
            // nonblocking mode
            let sock_clone = sock.clone();
            let task = TOKIO_RUNTIME.spawn(async move {
                let res = sb.call(sa, None).await;
                let mut l = sock_clone.lock().unwrap();
                match res {
                    Ok(s) => *l = SocketData::Established(s, options),
                    Err(e) => *l = SocketData::ConnectFailed(e),
                }
            });
            *l = SocketData::ConnectingNonBlocking(task, options);
        }
    } else {
        *l = sd; // restore state
        return set_error("Connect already called, invalid");
    }

    0
}

#[no_mangle]
pub extern "C" fn srt_accept(
    sock: SRTSOCKET,
    _addr: &mut libc::sockaddr,
    _addrlen: &mut c_int,
) -> SRTSOCKET {
    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    if let SocketData::Listening(ref mut l, opts) = *l {
        TOKIO_RUNTIME.block_on(async {
            let req = if opts.rcv_syn {
                // blocking
                match l.incoming().next().await {
                    Some(req) => req,
                    None => return set_error("Listener ended"),
                }
            } else {
                // nonblocking--10ms for now but could be shorter potentially
                match timeout(Duration::from_millis(10), l.incoming().next()).await {
                    Err(_) => return set_error("no new connections available"),
                    Ok(Some(req)) => req,
                    Ok(None) => return set_error("Listener ended"),
                }
            };
            // TODO: acceptors
            let srt_socket = req.accept(None).await.unwrap();
            // TODO: are options inhereted like this?
            insert_socket(SocketData::Established(srt_socket, opts))
        })
    } else {
        return set_error("Listen was not called");
    }
}

fn set_error(err: &str) -> c_int {
    LAST_ERROR.with(|l| {
        *l.borrow_mut() = CString::new(err).unwrap();
    });
    SRT_ERROR
}

thread_local! {
    pub static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("(no error set on this thread)").unwrap());
}

#[no_mangle]
pub extern "C" fn srt_getlasterror_str() -> *const c_char {
    LAST_ERROR.with(|f| f.borrow().as_c_str().as_ptr())
}

#[no_mangle]
pub extern "C" fn srt_send(_sock: SRTSOCKET, _buf: *const c_char, _len: c_int) -> c_int {
    todo!()
}

#[no_mangle]
pub extern "C" fn srt_sendmsg2(
    sock: SRTSOCKET,
    buf: *const c_char,
    len: c_int,
    _mctrl: Option<&SRT_MSGCTRL>,
) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    match *l {
        SocketData::Established(ref mut sock, _opts) => {
            // TODO: implement blocking mode
            // TODO: use _mctrl
            if let Err(_) = sock.try_send(
                Instant::now(),
                Bytes::copy_from_slice(unsafe { from_raw_parts(buf as *const u8, len as usize) }),
            ) {
                return set_error("Failed to send, sender buffer full");
            }
        }
        _ => return set_error("Connection not established, cannot send"),
    }

    0
}

/// Returns the number of bytes read
#[no_mangle]
pub extern "C" fn srt_recv(sock: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
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
                    Err(_) => return set_error("no data to receive"),
                    Ok(d) => d,
                }
            };

            let (_, recvd) = match d {
                Some(Ok(d)) => d,
                Some(Err(e)) => return set_error(&format!("failed to receive message: {}", e)),
                None => return set_error("stream ended permanantly"),
            };

            if bytes.len() < recvd.len() {
                error!("Receive buffer was not large enough, truncating...");
            }

            let bytes_to_write = min(bytes.len(), recvd.len());
            bytes[..bytes_to_write].copy_from_slice(&recvd[..bytes_to_write]);
            bytes_to_write as c_int
        })
    } else {
        set_error("Socket not connected")
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
pub extern "C" fn srt_create_socket() -> SRTSOCKET {
    insert_socket(SocketData::Initialized(
        Default::default(),
        Default::default(),
    ))
}

#[no_mangle]
pub extern "C" fn srt_setloglevel(_ll: c_int) {
    todo!()
}

#[no_mangle]
pub extern "C" fn srt_setsockopt(
    _sock: SRTSOCKET,
    _level: c_int, // unused
    _optname: SRT_SOCKOPT,
    _optval: *const (),
    _optlen: c_int,
) -> c_int {
    todo!()
}

unsafe fn extract_int(val: *const (), len: c_int) -> Option<c_int> {
    if len != 4 {
        return None;
    }
    Some((val as *const c_int).read())
}

unsafe fn extract_bool(val: *const (), len: c_int) -> Option<bool> {
    extract_int(val, len).map(|i| match i {
        0 => false,
        1 => true,
        o => {
            warn!("Warning: bool should be 1 or 0, not {}. Assuming true", o);
            true
        }
    })
}

#[no_mangle]
pub extern "C" fn srt_setsockflag(
    sock: SRTSOCKET,
    opt: SRT_SOCKOPT,
    optval: *const (),
    optlen: c_int,
) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let sock = sock.lock().unwrap();
    use SocketData::*;
    use SRT_SOCKOPT::*;
    match opt {
        SRTO_SENDER => {}
        SRTO_RCVSYN => match *sock {
            Initialized(_, mut o) | ConnectingNonBlocking(_, mut o) | Established(_, mut o) => {
                o.rcv_syn = match unsafe { extract_bool(optval, optlen) } {
                    Some(e) => e,
                    None => {
                        return set_error(&format!(
                            "Failed to set option: {:?}: wrong data length",
                            opt
                        ))
                    }
                }
            }
            Listening(_, _) | ConnectFailed(_) | InvalidIntermediateState => {
                return set_error(&format!("Option {:?} not settable in current state ", opt))
            }
        },
        o => unimplemented!("{:?}", o),
    }
    0
}

#[no_mangle]
pub extern "C" fn srt_close(socknum: SRTSOCKET) -> c_int {
    let sock = match get_sock(socknum) {
        None => return set_error("Invalid socket"),
        Some(sock) => sock,
    };

    let mut retcode = 0;

    let mut l = sock.lock().unwrap();
    if let SocketData::Established(ref mut s, _) = *l {
        let res = TOKIO_RUNTIME.block_on(async move { s.close().await });
        if let Err(e) = res {
            set_error(&format!("Failed to close socket: {}", e));
            retcode = SRT_ERROR;
        }
    }

    let mut sockets = SOCKETS.write().unwrap();
    sockets.remove(&socknum);

    retcode
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
