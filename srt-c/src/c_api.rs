#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::epoll::EpollFlags;
use crate::errors::{SRT_ERRNO, SRT_ERRNO::*};
use crate::socket::{CSrtSocket, SocketData};

use std::{
    cell::RefCell,
    cmp::min,
    collections::BTreeMap,
    ffi::CString,
    fmt::{Debug, Display},
    io::Write,
    mem::{size_of, take, MaybeUninit},
    os::raw::{c_char, c_int},
    ptr::{self, NonNull},
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use tokio::{
    runtime::{self, Runtime},
    time::timeout,
};

use bytes::Bytes;
use futures::StreamExt;
use lazy_static::lazy_static;
use log::error;
use os_socketaddr::OsSocketAddr;
use srt_protocol::options::SrtVersion;

use crate::epoll::SrtEpoll;

// NOTE: would love for this to be BorrowedFd,
// but cbindgen can't see its definition :(
pub type SYSSOCKET = c_int;
pub type SRTSOCKET = CSrtSocket;

pub type srt_listen_callback_fn = extern "C" fn(
    opaq: *mut (),
    ns: SRTSOCKET,
    c_int,
    peeraddr: *const libc::sockaddr,
    streamid: *const c_char,
) -> c_int;

pub struct SrtError {
    errno: SRT_ERRNO,
    context: String,
}

impl SrtError {
    pub fn new(errno: SRT_ERRNO, context: impl Display) -> SrtError {
        SrtError {
            errno,
            context: context.to_string(),
        }
    }
}

impl From<SRT_ERRNO> for SrtError {
    fn from(e: SRT_ERRNO) -> Self {
        SrtError::new(e, "")
    }
}

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
pub const SRT_INVALID_SOCK: CSrtSocket = CSrtSocket::INVALID;

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
    pub static ref TOKIO_RUNTIME: Runtime = {
        let rt = runtime::Builder::new_multi_thread().worker_threads(3).enable_all().build().unwrap();

        #[cfg(feature = "console-subscriber")]
        console_subscriber::init();
        rt
    };
    static ref SOCKETS: RwLock<BTreeMap<CSrtSocket, Arc<Mutex<SocketData>>>> =
        RwLock::new(BTreeMap::new());

    static ref BASE_TIME: Instant = Instant::now();
}

pub fn get_sock(sock: CSrtSocket) -> Option<Arc<Mutex<SocketData>>> {
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
        None => return set_error(SrtError::new(SRT_EINVPARAM, "Invalid socket address")),
    };
    let name = unsafe { OsSocketAddr::copy_from_raw(name, namelen.try_into().unwrap()) };
    let name = match name.into_addr() {
        Some(name) => name,
        None => return set_error(SRT_EINVPARAM.into()),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    if let SocketData::Initialized(ref mut b, _, _) = *l {
        b.connect.local = name;
        SRT_SUCCESS
    } else {
        set_error(SRT_ECONNSOCK.into())
    }
}

#[no_mangle]
pub extern "C" fn srt_listen(sock: SRTSOCKET, _backlog: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let mut l = sock.lock().unwrap();
    handle_result(l.listen(sock.clone()))
}

pub type SRT_EPOLL_OPT = c_int;
pub const SRT_EPOLL_OPT_NONE: c_int = 0x0;
pub const SRT_EPOLL_IN: c_int = 0x1;
pub const SRT_EPOLL_OUT: c_int = 0x4;
pub const SRT_EPOLL_ERR: c_int = 0x8;
pub const SRT_EPOLL_UPDATE: c_int = 0x10;
pub const SRT_EPOLL_ET: c_int = 1 << 31;

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
        .or_insert_with(|| Arc::new(Mutex::new(SrtEpoll::default())));
    id
}

#[no_mangle]
pub extern "C" fn srt_epoll_add_usock(
    eid: c_int,
    sock: SRTSOCKET,
    events: Option<&c_int>,
) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID.into()),
        Some(sock) => sock,
    };

    let flags = match events.copied().and_then(EpollFlags::from_bits) {
        Some(flags) => flags,
        None => return set_error(SRT_EINVPARAM.into()),
    };

    let mut l = epoll.lock().unwrap();
    l.add_srt(sock, flags);
    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_epoll_add_ssock(eid: c_int, s: SYSSOCKET, events: Option<&c_int>) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID.into()),
        Some(sock) => sock,
    };

    let flags = match events.copied().and_then(EpollFlags::from_bits) {
        Some(flags) => flags,
        None => return set_error(SRT_EINVPARAM.into()),
    };

    let mut l = epoll.lock().unwrap();
    l.add_sys(s, flags);

    SRT_SUCCESS
}

#[no_mangle]
pub extern "C" fn srt_epoll_remove_usock(eid: c_int, sock: SRTSOCKET) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID.into()),
        Some(sock) => sock,
    };

    let mut l = epoll.lock().unwrap();
    handle_result(l.remove_srt(sock))
}

#[no_mangle]
pub extern "C" fn srt_epoll_update_usock(
    eid: c_int,
    u: SRTSOCKET,
    events: Option<&c_int>,
) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID.into()),
        Some(sock) => sock,
    };

    let flags = match events.copied().and_then(EpollFlags::from_bits) {
        Some(flags) => flags,
        None => return set_error(SRT_EINVPARAM.into()),
    };

    let mut l = epoll.lock().unwrap();
    handle_result(l.update_srt(u, flags))
}

#[no_mangle]
pub extern "C" fn srt_epoll_release(eid: c_int) -> c_int {
    if EPOLLS.write().unwrap().remove(&eid).is_none() {
        return set_error(SRT_EINVPOLLID.into());
    }
    SRT_SUCCESS
}

/// # Safety
/// * `(r|w)num` is not null
/// * `(read|write)fds` points to a valid array of `*(r|w)num` elemens
#[no_mangle]
pub unsafe extern "C" fn srt_epoll_wait(
    eid: c_int,
    readfds: *mut SRTSOCKET,
    rnum: Option<&mut c_int>,
    writefds: *mut SRTSOCKET,
    wnum: Option<&mut c_int>,
    msTimeOut: i64,
    lrfds: *mut SYSSOCKET,
    lrnum: Option<&mut c_int>,
    lwfds: *mut SYSSOCKET,
    lwnum: Option<&mut c_int>,
) -> c_int {
    let epoll = match get_epoll(eid) {
        None => return set_error(SRT_EINVPOLLID.into()),
        Some(sock) => sock,
    };

    let mut l = epoll.lock().unwrap();

    let srt_read = if !readfds.is_null() && rnum.is_some() {
        from_raw_parts_mut(
            readfds as *mut MaybeUninit<CSrtSocket>,
            *rnum.as_deref().unwrap() as usize,
        )
    } else {
        &mut []
    };
    let srt_write = if !writefds.is_null() && wnum.is_some() {
        from_raw_parts_mut(
            writefds as *mut MaybeUninit<CSrtSocket>,
            *wnum.as_deref().unwrap() as usize,
        )
    } else {
        &mut []
    };

    let sys_read = if !lrfds.is_null() && lrnum.is_some() {
        from_raw_parts_mut(
            lrfds as *mut MaybeUninit<SYSSOCKET>,
            *lrnum.as_deref().unwrap() as usize,
        )
    } else {
        &mut []
    };

    let sys_write = if !lwfds.is_null() && lwnum.is_some() {
        from_raw_parts_mut(
            lwfds as *mut MaybeUninit<SYSSOCKET>,
            *lwnum.as_deref().unwrap() as usize,
        )
    } else {
        &mut []
    };

    let timeout = msTimeOut.try_into().map(Duration::from_millis).ok();

    match l.wait(srt_read, srt_write, sys_read, sys_write, timeout) {
        Ok((srt_rnum, srt_wnum, sys_rnum, sys_wnum)) => {
            if let Some(rnum) = rnum {
                *rnum = srt_rnum.try_into().unwrap();
            }
            if let Some(wnum) = wnum {
                *wnum = srt_wnum.try_into().unwrap();
            }
            if let Some(lrnum) = lrnum {
                *lrnum = sys_rnum.try_into().unwrap();
            }
            if let Some(lwnum) = lwnum {
                *lwnum = sys_wnum.try_into().unwrap();
            }

            (srt_rnum + srt_wnum + sys_rnum + sys_wnum)
                .try_into()
                .unwrap()
        }
        Err(e) => set_error(e),
    }
}

#[no_mangle]
pub extern "C" fn srt_epoll_uwait(
    _eid: c_int,
    _fdsSet: *mut SRT_EPOLL_EVENT,
    _fdsSize: c_int,
    _msTimeOut: i64,
) -> c_int {
    todo!()
}

#[no_mangle]
pub extern "C" fn srt_connect(
    sock: SRTSOCKET,
    name: Option<&libc::sockaddr>,
    namelen: c_int,
) -> c_int {
    let name = match name {
        Some(name) => name,
        None => return set_error(SrtError::new(SRT_EINVPARAM, "Invalid socket address")),
    };
    let name = unsafe {
        OsSocketAddr::copy_from_raw(
            name,
            min(
                namelen.try_into().unwrap(),
                size_of::<libc::sockaddr_in6>() as u32,
            ),
        )
    };
    let name = match name.into_addr() {
        Some(name) => name,
        None => return set_error(SRT_EINVPARAM.into()),
    };

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let l = sock.lock().unwrap();
    handle_result(SocketData::connect(l, sock.clone(), name))
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
        (Some(_), None) => {
            set_error(SRT_EINVPARAM.into());
            return SRT_INVALID_SOCK;
        }
    };

    let sock = match get_sock(sock) {
        None => {
            set_error(SRT_EINVSOCK.into());
            return SRT_INVALID_SOCK;
        }
        Some(sock) => sock,
    };

    let l = sock.lock().unwrap();
    match SocketData::accept(l, sock.clone()) {
        Ok((sock, remote)) => {
            if let Some((addr, len)) = addr {
                let osa = OsSocketAddr::from(remote);
                *addr = unsafe { *(osa.as_ptr() as *const libc::sockaddr) };
                *len = osa.len() as c_int;
            }
            sock
        }
        Err(e) => {
            set_error(e);
            SRT_INVALID_SOCK
        }
    }
}

fn set_error(err: SrtError) -> c_int {
    LAST_ERROR_STR.with(|l| {
        // it's a bit of gymnastics to reuse the buffer, but totally worth it!
        let mut m = l.borrow_mut();
        let mut vec = take(&mut *m).into_bytes_with_nul();
        vec.clear();
        write!(&mut vec, "{:?}: {}", err.errno, err.context).unwrap();
        vec.push(b'\0');
        *m = CString::from_vec_with_nul(vec).unwrap();
    });
    LAST_ERROR.with(|l| *l.borrow_mut() = err.errno);
    SRT_ERROR
}

fn handle_result(res: Result<(), SrtError>) -> c_int {
    match res {
        Ok(_) => SRT_SUCCESS,
        Err(err) => set_error(err),
    }
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
        None => return set_error(SRT_EINVSOCK.into()),
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
                return set_error(SRT_ELARGEMSG.into());
            }
        }
        _ => return set_error(SRT_ENOCONN.into()),
    }

    len
}

/// Returns the number of bytes read
#[no_mangle]
pub extern "C" fn srt_recv(sock: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int {
    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK.into()),
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
                    Err(_) => return set_error(SRT_EASYNCRCV.into()),
                    Ok(d) => d,
                }
            };

            let (_, recvd) = match d {
                Some(Ok(d)) => d,
                Some(Err(e)) => return set_error(SrtError::new(SRT_ECONNLOST, e)), // TODO: not sure which error exactly here
                None => return set_error(SRT_ECONNLOST.into()),
            };

            if bytes.len() < recvd.len() {
                error!("Receive buffer was not large enough, truncating...");
            }

            let bytes_to_write = min(bytes.len(), recvd.len());
            bytes[..bytes_to_write].copy_from_slice(&recvd[..bytes_to_write]);
            bytes_to_write as c_int
        })
    } else {
        set_error(SRT_ENOCONN.into())
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

pub fn insert_socket(data: SocketData) -> CSrtSocket {
    let mut sockets = SOCKETS.write().unwrap();
    let new_sockid = CSrtSocket::new_unused();
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
    let _level = match ll {
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
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let mut sock = sock.lock().unwrap();
    handle_result(sock.set_flag(opt, optval, optlen))
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

    let sock = match get_sock(sock) {
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let optval_len = match optlen.as_ref().map(|&&mut i| i.try_into()) {
        Some(Ok(len)) => len,
        Some(Err(_)) => return set_error(SrtError::new(SRT_EINVPARAM, "optlen was negative")), // negative size, woah
        None => 0,
    };

    let l = sock.lock().unwrap();
    match l.get_flag(opt, optval, optval_len) {
        Ok(len) => {
            if let Some(ol) = optlen {
                *ol = len.try_into().expect("returned >2GiB, strange");
            }
            SRT_SUCCESS
        }
        Err(e) => set_error(e),
    }
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
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };
    let mut l = sock.lock().unwrap();
    handle_result(l.listen_callback(hook_fn, hook_opaque))
}

#[no_mangle]
pub extern "C" fn srt_time_now() -> i64 {
    (Instant::now() - *BASE_TIME)
        .as_micros()
        .try_into()
        .expect("did not expect program to run for 2^63 us")
}

#[no_mangle]
pub extern "C" fn srt_close(socknum: SRTSOCKET) -> c_int {
    let sock = match get_sock(socknum) {
        None => return set_error(SRT_EINVSOCK.into()),
        Some(sock) => sock,
    };

    let mut retcode = SRT_SUCCESS;

    let mut l = sock.lock().unwrap();
    match &mut *l {
        SocketData::Established(ref mut s, _) => {
            let res = TOKIO_RUNTIME.block_on(async move { s.close_and_finish().await });
            if let Err(e) = res {
                retcode = set_error(SrtError::new(
                    SRT_EINVOP,
                    format_args!("Failed to close socket: {e}"),
                ));
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
