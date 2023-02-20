use std::{
    ffi::CString,
    io,
    mem::{self, replace, size_of},
    net::SocketAddr,
    os::raw::c_char,
    os::raw::c_int,
    ptr::{self, NonNull},
    slice,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::Poll,
    time::Duration, cmp::min,
};

use futures::{
    channel::mpsc, future::Shared, poll, stream::Peekable, FutureExt, SinkExt, StreamExt,
};
use log::{warn, error};
use os_socketaddr::OsSocketAddr;
use srt_protocol::{
    connection::ConnectionSettings,
    options::{
        DataRate, ListenerOptions, LiveBandwidthMode, PacketSize, Percent, Sender, SocketOptions,
        StreamId, Validation,
    },
    settings::{KeySettings, KeySize, Passphrase},
};
use srt_tokio::{SrtListener, SrtSocket};
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle, time::timeout};

use crate::c_api::{
    get_sock, insert_socket, srt_close, srt_listen_callback_fn, SrtError, SRTSOCKET, SRT_SOCKOPT,
    TOKIO_RUNTIME, SRT_MSGCTRL,
};
use crate::errors::SRT_ERRNO::{self, *};

static NEXT_SOCKID: AtomicI32 = AtomicI32::new(1);

extern "C" {
    pub fn call_callback_wrap_exception(
        func: srt_listen_callback_fn,
        opaq: *mut (),
        ns: SRTSOCKET,
        hsversion: c_int,
        peeraddr: *const libc::sockaddr,
        streamid: *const c_char,
        ret: *mut c_int,
    ) -> c_int;
}

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct CSrtSocket(i32);

#[derive(Debug)]
pub enum SocketData {
    Initialized(SocketOptions, Option<StreamId>, ApiOptions),
    Bound(SocketOptions, UdpSocket, Option<StreamId>, ApiOptions),
    ConnectingNonBlocking(Shared<tokio::sync::oneshot::Receiver<()>>, ApiOptions),
    Established(SrtSocket, ApiOptions),
    Listening(
        SrtListener,
        Option<Peekable<mpsc::Receiver<(CSrtSocket, SocketAddr)>>>,
        JoinHandle<()>,
        ApiOptions,
    ),
    ConnectFailed(io::Error),

    Accepting(Option<KeySettings>),

    InvalidIntermediateState,
    Closed,
}

#[derive(Clone, Copy, Debug)]
pub struct ApiOptions {
    pub snd_syn: bool, // corresponds to SRTO_SNDSYN
    pub rcv_syn: bool, // corresponds to SRTO_RCVSYN
    pub listen_cb: Option<srt_listen_callback_fn>,
    pub listen_cb_opaque: *mut (),
}

impl CSrtSocket {
    pub const INVALID: CSrtSocket = CSrtSocket(-1);

    pub fn new_unused() -> CSrtSocket {
        let sockid = NEXT_SOCKID.fetch_add(1, Ordering::SeqCst);
        assert!(sockid > 0); // wrapped around, no good!!
        CSrtSocket(sockid)
    }
}

unsafe fn extract_int(val: NonNull<()>, len: c_int) -> Result<c_int, SRT_ERRNO> {
    if len as usize == mem::size_of::<c_int>() {
        return Ok(*val.cast::<c_int>().as_ref());
    }
    Err(SRT_EINVPARAM)
}

unsafe fn extract_i64(val: NonNull<()>, len: c_int) -> Result<i64, SRT_ERRNO> {
    if len as usize == mem::size_of::<i64>() {
        return Ok(*val.cast::<i64>().as_ref());
    }
    Err(SRT_EINVPARAM)
}

unsafe fn extract_bool(val: NonNull<()>, len: c_int) -> Result<bool, SRT_ERRNO> {
    match len {
        4 => match extract_int(val, len)? {
            0 => Ok(false),
            1 => Ok(true),
            o => {
                warn!("Warning: bool should be 1 or 0, not {}. Assuming true", o);
                Ok(true)
            }
        },
        1 => match *val.cast::<u8>().as_ref() {
            0 => Ok(false),
            1 => Ok(true),
            o => {
                warn!("Warning: bool should be 1 or 0, not {}. Assuming true", o);
                Ok(true)
            }
        },
        _ => Err(SRT_EINVPARAM),
    }
}

unsafe fn extract_str(val: NonNull<()>, len: c_int) -> Result<String, SRT_ERRNO> {
    let slice = slice::from_raw_parts(val.as_ptr() as *const u8, len as usize);
    String::from_utf8(slice.into()).map_err(|_| SRT_EINVPARAM)
}

impl SocketData {
    fn api_opts(&self) -> Option<&ApiOptions> {
        use SocketData::*;
        match self {
            Initialized(_, _, opts)
            | Bound(_, _, _, opts)
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
            Initialized(so, _, ai) | Bound(so, _, _, ai) => (Some(ai), Some(so)),
            ConnectingNonBlocking(_, ai) | Established(_, ai) | Listening(_, _, _, ai) => {
                (Some(ai), None)
            }
            _ => (None, None),
        }
    }

    pub unsafe fn set_flag(
        &mut self,
        opt: SRT_SOCKOPT,
        optval: Option<NonNull<()>>,
        optlen: c_int,
    ) -> Result<(), SrtError> {
        use SRT_SOCKOPT::*;

        let optval = match optval {
            Some(ov) => ov,
            None => return Err(SrtError::new(SRT_EINVPARAM, "optval was null")),
        };

        if let SocketData::Accepting(ref mut params) = self {
            match opt {
                SRTO_PASSPHRASE => {
                    *params = Some(KeySettings {
                        passphrase: Passphrase::try_from(extract_str(optval, optlen)?)
                            .map_err(|_| SRT_EINVPARAM)?,
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
            return Ok(());
        }

        if opt == SRTO_STREAMID {
            if let SocketData::Initialized(_, ref mut init, _) = self {
                *init = Some(
                    extract_str(optval, optlen)?
                        .try_into()
                        .map_err(|_| SRT_EINVPARAM)?,
                );
                return Ok(());
            }
            return Err(SRT_ECONNSOCK.into());
        }

        match (opt, self.opts_mut()) {
            (SRTO_SENDER, (_, _)) => {}
            (SRTO_RCVSYN, (Some(o), _)) => {
                o.rcv_syn = extract_bool(optval, optlen)?;
            }
            (SRTO_SNDSYN, (Some(o), _)) => {
                o.snd_syn = extract_bool(optval, optlen)?;
            }
            (SRTO_CONNTIMEO, (_, Some(o))) => {
                o.connect.timeout = Duration::from_millis(
                    extract_int(optval, optlen)?
                        .try_into()
                        .map_err(|_| SRT_EINVPARAM)?,
                );
            }
            (SRTO_TSBPDMODE, _) => {
                if !extract_bool(optval, optlen)? {
                    return Err(SrtError::new(
                        SRT_EINVOP,
                        "tsbpd mode is required in srt-rs",
                    )); // tsbpd=false is not implemented
                }
            }
            (SRTO_PASSPHRASE, (_, Some(o))) => {
                let pwd = extract_str(optval, optlen)?;
                if pwd.is_empty() {
                    o.encryption.passphrase = None;
                } else {
                    o.encryption.passphrase = Some(pwd.try_into().map_err(|_| SRT_EINVPARAM)?);
                }
            }
            (SRTO_RCVLATENCY, (_, Some(o))) => {
                o.receiver.latency = Duration::from_millis(
                    extract_int(optval, optlen)?
                        .try_into()
                        .map_err(|_| SRT_EINVPARAM)?,
                );
            }
            (SRTO_PEERLATENCY, (_, Some(o))) => {
                o.sender.peer_latency = Duration::from_millis(
                    extract_int(optval, optlen)?
                        .try_into()
                        .map_err(|_| SRT_EINVPARAM)?,
                );
            }
            (SRTO_MININPUTBW, (_, Some(o))) => {
                o.sender.bandwidth = LiveBandwidthMode::Estimated {
                    expected: DataRate(
                        extract_i64(optval, optlen)?
                            .try_into()
                            .map_err(|_| SRT_EINVPARAM)?,
                    ),
                    overhead: match o.sender.bandwidth {
                        LiveBandwidthMode::Estimated { overhead, .. } => overhead,
                        _ => Percent(25), // TODO: what should this be
                    },
                }
            }
            (SRTO_PAYLOADSIZE, (_, Some(o))) => {
                o.sender.max_payload_size = PacketSize(
                    extract_int(optval, optlen)?
                        .try_into()
                        .map_err(|_| SRT_EINVPARAM)?,
                );
            }
            (o, _) => unimplemented!("{:?}", o),
        }
        Ok(())
    }

    pub unsafe fn get_flag(
        &self,
        opt: SRT_SOCKOPT,
        optval: Option<NonNull<()>>,
        optval_len: usize,
    ) -> Result<usize, SrtError> {
        let optval = match optval {
            Some(ov) => ov,
            None => return Err(SrtError::new(SRT_EINVPARAM, "optval was null")),
        };

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
            match self {
                SocketData::Initialized(_, sid, _) => {
                    Str(sid.as_ref().map(|s| s.as_str()).unwrap_or(""))
                }
                SocketData::Established(sock, _) => {
                    Str(sock.settings().stream_id.as_deref().unwrap_or(""))
                }
                _ => return Err(SRT_EBOUNDSOCK.into()),
            }
        } else {
            match (opt, self.api_opts(), self.sock_opts(), self.conn_settings()) {
                (SRTO_RCVSYN, Some(opts), _, _) => Bool(opts.rcv_syn),
                (SRTO_SNDSYN, Some(opts), _, _) => Bool(opts.snd_syn),
                (SRTO_CONNTIMEO, _, Some(opts), _) => {
                    Int(opts.connect.timeout.as_millis() as c_int)
                }
                (SRTO_RCVLATENCY, _, Some(opts), _) => {
                    Int(opts.receiver.latency.as_millis() as c_int)
                }
                (SRTO_RCVLATENCY, _, _, Some(cs)) => {
                    Int(cs.recv_tsbpd_latency.as_millis() as c_int)
                }
                (SRTO_PEERLATENCY, _, Some(opts), _) => {
                    Int(opts.sender.peer_latency.as_millis() as c_int)
                }
                (SRTO_PEERLATENCY, _, _, Some(cs)) => {
                    Int(cs.send_tsbpd_latency.as_millis() as c_int)
                }
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
                _ => unimplemented!("{:?} {:?}", opt, self),
            }
        };

        match val {
            Bool(b) => {
                if optval_len != size_of::<c_int>() {
                    return Err(SRT_EINVPARAM.into());
                }
                *optval.cast::<c_int>().as_mut() = if b { 1 } else { 0 };
                Ok(size_of::<c_int>())
            }
            Int(i) => {
                if optval_len < size_of::<c_int>() {
                    return Err(SRT_EINVPARAM.into());
                }
                *optval.cast::<c_int>().as_mut() = i;
                Ok(size_of::<c_int>())
            }
            Int64(i) => {
                if optval_len < size_of::<i64>() {
                    return Err(SRT_EINVPARAM.into());
                }
                *optval.cast::<i64>().as_mut() = i;
                Ok(size_of::<i64>())
            }
            Str(str) => {
                if optval_len < (str.as_bytes().len() + 1) {
                    return Err(SRT_EINVPARAM.into());
                }
                let optval = slice::from_raw_parts_mut(optval.cast::<u8>().as_mut(), optval_len);
                optval[..str.as_bytes().len()].copy_from_slice(str.as_bytes());
                optval[str.as_bytes().len()] = 0; // null terminator
                Ok(str.as_bytes().len())
            }
        }
    }

    pub fn listen(&mut self, sock: Arc<Mutex<SocketData>>) -> Result<(), SrtError> {
        let sd = replace(self, SocketData::InvalidIntermediateState);
        if let SocketData::Bound(so, socket, _, initial_opts) = sd {
            let options = ListenerOptions { socket: so }
                .try_validate()
                .map_err(|e| SrtError::new(SRT_EINVOP, e))?;
            let (listener, mut incoming) = TOKIO_RUNTIME
                .block_on(SrtListener::bind_with_socket(options, socket))
                .map_err(|e| SrtError::new(SRT_EINVOP, e))?;

            let (mut s, r) = mpsc::channel(1024);
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
            *self = SocketData::Listening(listener, Some(r.peekable()), task, initial_opts)
        } else {
            *self = sd;
            return Err(SRT_ECONNSOCK.into());
        }

        Ok(())
    }

    pub fn connect(
        mut l: MutexGuard<SocketData>,
        handle: Arc<Mutex<SocketData>>,
        sa: SocketAddr,
    ) -> Result<(), SrtError> {
        let sd = replace(&mut *l, SocketData::InvalidIntermediateState);

        if let SocketData::Initialized(so, streamid, options) = sd {
            let sb = SrtSocket::builder().with(so.clone());
            if options.rcv_syn {
                drop(l); // drop lock to avoid holding lock during blocking call

                // blocking mode, wait on oneshot
                let sock = TOKIO_RUNTIME
                    .block_on(async { sb.call(sa, streamid.as_ref().map(|s| s.as_str())).await })
                    .map_err(|e| SrtError::new(SRT_ENOSERVER, e));

                let mut l = handle.lock().unwrap();
                match sock {
                    Ok(sock) => {
                        *l = SocketData::Established(sock, options);
                        Ok(())
                    }
                    Err(e) => {
                        *l = SocketData::Initialized(so, streamid, options);
                        Err(e)
                    }
                }
            } else {
                // nonblocking mode

                let (done_s, done_r) = oneshot::channel();
                TOKIO_RUNTIME.spawn(async move {
                    let res = sb.call(sa, None).await;
                    let mut l = handle.lock().unwrap();
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
                Ok(())
            }
        } else {
            *l = sd; // restore state
            Err(SRT_ECONNSOCK.into())
        }
    }

    pub fn accept(
        mut l: MutexGuard<SocketData>,
        handle: Arc<Mutex<SocketData>>,
    ) -> Result<(CSrtSocket, SocketAddr), SrtError> {
        if let SocketData::Listening(ref _listener, ref mut incoming, ref _jh, opts) = *l {
            let mut incoming = incoming.take().ok_or_else(|| {
                SrtError::new(
                    SRT_EINVOP,
                    "accept can only be called from one thread at a time",
                )
            })?;

            drop(l); // release mutex so other calls don't block
            let (new_sock, addr) = TOKIO_RUNTIME
                .block_on(async {
                    if opts.rcv_syn {
                        Ok(incoming.next().await)
                    } else {
                        match poll!(incoming.next()) {
                            Poll::Pending => Err(SRT_EASYNCFAIL),
                            Poll::Ready(r) => Ok(r),
                        }
                    }
                })?
                .ok_or_else(|| SrtError::new(SRT_ESCLOSED, "accepting socket closed"))?;

            // put listener back
            {
                let mut l = handle.lock().unwrap();
                if let SocketData::Listening(_listener, in_state, _jh, _opts) = &mut *l {
                    *in_state = Some(incoming);
                }
            }
            Ok((new_sock, addr))
        } else {
            Err(SRT_ENOLISTEN.into())
        }
    }

    pub fn recv(mut l: MutexGuard<SocketData>, bytes: &mut [u8], mctrl: Option<&mut SRT_MSGCTRL>) -> Result<usize, SrtError> {
        if let SocketData::Established(ref mut sock, opts) = *l {
            TOKIO_RUNTIME.block_on(async {
                let d = if opts.rcv_syn {
                    // block
                    sock.next().await
                } else {
                    // nonblock
                    match timeout(Duration::from_millis(10), sock.next()).await {
                        Err(_) => return Err(SRT_EASYNCRCV.into()),
                        Ok(d) => d,
                    }
                };

                let (_, recvd) = match d {
                    Some(Ok(d)) => d,
                    Some(Err(e)) => return Err(SrtError::new(SRT_ECONNLOST, e)), // TODO: not sure which error exactly here
                    None => return Err(SRT_ECONNLOST.into()),
                };

                if bytes.len() < recvd.len() {
                    error!("Receive buffer was not large enough, truncating...");
                }

                let bytes_to_write = min(bytes.len(), recvd.len());
                bytes[..bytes_to_write].copy_from_slice(&recvd[..bytes_to_write]);
                Ok(bytes_to_write)
            })
        } else {
            Err(SRT_ENOCONN.into())
        }
    }

    pub unsafe fn listen_callback(
        &mut self,
        hook_fn: srt_listen_callback_fn,
        hook_opaque: *mut (),
    ) -> Result<(), SrtError> {
        if let (Some(o), _) = self.opts_mut() {
            o.listen_cb = Some(hook_fn);
            o.listen_cb_opaque = hook_opaque;
            Ok(())
        } else {
            Err(SRT_ENOCONN.into()) // TODO: which error here?
        }
    }
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
