use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use futures::future::{poll_fn, Ready};
use futures::{pending, poll, SinkExt};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::pin;
use tokio::time::sleep;

use crate::errors::SRT_ERRNO::*;
use crate::socket::{CSrtSocket, SocketData};
use crate::{get_sock, SrtError};
use crate::{SYSSOCKET, TOKIO_RUNTIME};

#[derive(Debug)]
enum SrtEpollEntry {
    Srt(CSrtSocket, EpollFlags),
    Sys(AsyncFd<SYSSOCKET>, EpollFlags),
}

#[derive(Default)]
pub struct SrtEpoll {
    socks: Vec<SrtEpollEntry>,
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
            Poll::Ready(Err(e)) => {
                log::error!("Got poll error: {:?}", e);
                ReadyPendingError::Error
            }
            Poll::Pending => ReadyPendingError::Pending,
        }
    }
}

impl<T> From<Poll<Option<T>>> for ReadyPendingError {
    fn from(s: Poll<Option<T>>) -> Self {
        match s {
            Poll::Ready(Some(_)) => ReadyPendingError::Ready,
            Poll::Ready(None) => {
                log::error!("got eos!");
                ReadyPendingError::Error
            }
            Poll::Pending => ReadyPendingError::Pending,
        }
    }
}

bitflags::bitflags! {

    pub struct EpollFlags: c_int {
        const SRT_EPOLL_OPT_NONE = 0x0; // fallback

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
        const IN = 0x1;
        const ACCEPT = EpollFlags::IN.bits();

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
        const OUT = 0x4;
        const CONNECT = EpollFlags::OUT.bits();

        /// The socket has encountered an error in the last operation
        /// and the next operation on that socket will end up with error.
        /// You can retry the operation, but getting the error from it
        /// is certain, so you may as well close the socket.
        const ERR = 0x8;

        const SRT_EPOLL_UPDATE = 0x10;
        const SRT_EPOLL_ET = 1 << 31;
    }
}

impl EpollFlags {
    fn to_interest(&self) -> Interest {
        match (
            self.contains(EpollFlags::IN),
            self.contains(EpollFlags::OUT),
        ) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (false, false) => panic!("interest must be either writable or readable"),
        }
    }
}

impl SrtEpoll {
    pub fn add_srt(&mut self, s: CSrtSocket, flags: EpollFlags) {
        self.socks.push(SrtEpollEntry::Srt(s, flags));
    }

    pub fn add_sys(&mut self, s: SYSSOCKET, flags: EpollFlags) {
        TOKIO_RUNTIME.block_on(async {
            self.socks.push(SrtEpollEntry::Sys(
                AsyncFd::with_interest(s, flags.to_interest()).unwrap(),
                flags,
            ));
        });
    }

    pub fn remove_srt(&mut self, sock: CSrtSocket) -> Result<(), SrtError> {
        match self
            .socks
            .iter()
            .position(|s| matches!(s, SrtEpollEntry::Srt(c, _) if *c == sock))
        {
            Some(p) => self.socks.remove(p),
            None => return Err(SRT_EINVSOCK.into()),
        };

        Ok(())
    }

    pub fn update_srt(&mut self, u: CSrtSocket, flags: EpollFlags) -> Result<(), SrtError> {
        for s in &mut self.socks {
            match s {
                SrtEpollEntry::Srt(sockid, _) if *sockid == u => {
                    *s = SrtEpollEntry::Srt(u, flags);
                    return Ok(());
                }
                _ => {}
            }
        }

        Err(SRT_EINVSOCK.into())
    }

    pub fn wait(
        &mut self,
        srt_read: &mut [MaybeUninit<CSrtSocket>],
        srt_write: &mut [MaybeUninit<CSrtSocket>],
        sys_read: &mut [MaybeUninit<SYSSOCKET>],
        sys_write: &mut [MaybeUninit<SYSSOCKET>],
        timeout: Option<Duration>,
    ) -> Result<(usize, usize, usize, usize), SrtError> {
        let sleep_fut = async {
            if let Some(to) = timeout {
                sleep(to).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        pin!(sleep_fut);

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

                // poll all the sockets
                // NOTE: don't await in this block, we need to not hold `sock_l` when we return pending() (below in the pending!() call)
                for (idx, epollentry) in self.socks.iter().enumerate() {
                    let socket_poll_res: Option<(
                        usize,
                        ReadyPendingError,
                        ReadyPendingError,
                        EpollFlags,
                    )> = match epollentry {
                        SrtEpollEntry::Srt(sock, flags) => {
                            let sock = match get_sock(*sock) {
                                Some(sock) => sock,
                                None => continue,
                            };

                            let mut sock_l = sock.lock().unwrap();

                            match &mut *sock_l {
                                SocketData::Established(sock, _opts) => {
                                    let (stream, mut sink) = sock.split_mut();

                                    let ready_recv = if flags.contains(EpollFlags::IN) {
                                        poll!(stream.peek()).into()
                                    } else {
                                        ReadyPendingError::Pending
                                    };
                                    let ready_send = if flags.contains(EpollFlags::OUT) {
                                        poll!(poll_fn(|cx| sink.poll_ready_unpin(cx))).into()
                                    } else {
                                        ReadyPendingError::Pending
                                    };

                                    Some((idx, ready_recv, ready_send, *flags))
                                }
                                SocketData::ConnectingNonBlocking(jh, _) => {
                                    let mut jh = jh.clone();

                                    let ready_send = if flags.contains(EpollFlags::CONNECT) {
                                        let ready_send = poll!(&mut jh).into();
                                        jhs.push(jh);
                                        ready_send
                                    } else {
                                        ReadyPendingError::Pending
                                    };
                                    Some((idx, ReadyPendingError::Pending, ready_send, *flags))
                                }
                                SocketData::Listening(_, i, _, _) => {
                                    if let Some(recv) = i {
                                        let ready_recv = if flags.contains(EpollFlags::ACCEPT) {
                                            poll!(Pin::new(recv).peek()).into()
                                        } else {
                                            ReadyPendingError::Pending
                                        };
                                        Some((idx, ready_recv, ReadyPendingError::Pending, *flags))
                                    } else {
                                        None
                                    }
                                }
                                SocketData::ConnectFailed(_) => Some((
                                    idx,
                                    if flags.contains(EpollFlags::ERR) { ReadyPendingError::Error } else { ReadyPendingError::Pending },
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
                            let ready_recv = if flags.contains(EpollFlags::IN) {
                                poll!(poll_fn(|cx| sock.poll_read_ready(cx)))
                                    .map_ok(|mut r| {
                                        r.clear_ready();
                                        r
                                    })
                                    .into()
                            } else {
                                ReadyPendingError::Pending
                            };
                            let ready_send = if flags.contains(EpollFlags::OUT) {
                                poll!(poll_fn(|cx| sock.poll_write_ready(cx)))
                                    .map_ok(|mut r| {
                                        r.clear_ready();
                                        r
                                    })
                                    .into()
                            } else {
                                ReadyPendingError::Pending
                            };

                            Some((idx, ready_recv, ready_send, *flags))
                        }
                    };

                    if let Some((idx, read, write, flags)) = socket_poll_res {
                        let out_requested = flags.contains(EpollFlags::OUT);
                        let in_requested = flags.contains(EpollFlags::IN);
                        let err_requested = flags.contains(EpollFlags::ERR);

                        let was_error =
                            read == ReadyPendingError::Error || write == ReadyPendingError::Error;

                        if (in_requested && read == ReadyPendingError::Ready)
                            || (err_requested && was_error)
                        {
                            match &self.socks[idx] {
                                SrtEpollEntry::Srt(fd, _) => {
                                    srt_read[written_rfds].write(*fd);
                                    written_rfds += 1;
                                }
                                SrtEpollEntry::Sys(fd, _) => {
                                    sys_read[written_lrfds].write(*fd.get_ref());
                                    written_lrfds += 1;
                                }
                            }
                        }

                        if (out_requested && write == ReadyPendingError::Ready)
                            || (err_requested && was_error)
                        {
                            match &self.socks[idx] {
                                SrtEpollEntry::Srt(fd, _) => {
                                    srt_write[written_wfds].write(*fd);
                                    written_wfds += 1;
                                }
                                SrtEpollEntry::Sys(fd, _) => {
                                    sys_write[written_lwfds].write(*fd.get_ref());
                                    written_lwfds += 1;
                                }
                            }
                        }
                    }
                }

                // see if timeout has been reached
                if let Poll::Ready(()) = poll!(&mut sleep_fut) {
                    break;
                }

                // if this loop got anything, then go for it
                // otherwise, return pending
                if written_rfds == 0
                    && written_wfds == 0
                    && written_lrfds == 0
                    && written_lwfds == 0
                {
                    pending!();
                    continue;
                } else {
                    break;
                }
            }

            Ok((written_rfds, written_wfds, written_lrfds, written_lwfds))
        })
    }
}
