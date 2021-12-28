use thiserror::Error;

#[repr(C)]
#[derive(Error, Debug, Clone, Copy)]
pub enum SRT_ERRNO {
    #[error("")]
    SRT_EUNKNOWN = -1,
    #[error("")]
    SRT_SUCCESS = 0,

    #[error("")]
    SRT_ECONNSETUP = 1000,
    #[error("")]
    SRT_ENOSERVER = 1001,
    #[error("")]
    SRT_ECONNREJ = 1002,
    #[error("")]
    SRT_ESOCKFAIL = 1003,
    #[error("")]
    SRT_ESECFAIL = 1004,
    #[error("")]
    SRT_ESCLOSED = 1005,

    #[error("")]
    SRT_ECONNFAIL = 2000,
    #[error("")]
    SRT_ECONNLOST = 2001,
    #[error("")]
    SRT_ENOCONN = 2002,

    #[error("")]
    SRT_ERESOURCE = 3000,
    #[error("")]
    SRT_ETHREAD = 3001,
    #[error("")]
    SRT_ENOBUF = 3002,
    #[error("")]
    SRT_ESYSOBJ = 3003,

    #[error("")]
    SRT_EFILE = 4000,
    #[error("")]
    SRT_EINVRDOFF = 4001,
    #[error("")]
    SRT_ERDPERM = 4002,
    #[error("")]
    SRT_EINVWROFF = 4003,
    #[error("")]
    SRT_EWRPERM = 4004,

    #[error("")]
    SRT_EINVOP = 5000,
    #[error("")]
    SRT_EBOUNDSOCK = 5001,
    #[error("The socket is already connected")]
    SRT_ECONNSOCK = 5002,
    #[error("")]
    SRT_EINVPARAM = 5003,
    #[error("Invalid socket ID")]
    SRT_EINVSOCK = 5004,
    #[error("")]
    SRT_EUNBOUNDSOCK = 5005,
    #[error("The socket was not setup as a listener (srt_listen was not called)")]
    SRT_ENOLISTEN = 5006,
    #[error("")]
    SRT_ERDVNOSERV = 5007,
    #[error("")]
    SRT_ERDVUNBOUND = 5008,
    #[error("")]
    SRT_EINVALMSGAPI = 5009,
    #[error("")]
    SRT_EINVALBUFFERAPI = 5010,
    #[error("")]
    SRT_EDUPLISTEN = 5011,
    #[error("")]
    SRT_ELARGEMSG = 5012,
    #[error("")]
    SRT_EINVPOLLID = 5013,
    #[error("")]
    SRT_EPOLLEMPTY = 5014,
    #[error("")]
    SRT_EBINDCONFLICT = 5015,

    #[error("")]
    SRT_EASYNCFAIL = 6000,
    #[error("")]
    SRT_EASYNCSND = 6001,
    #[error("")]
    SRT_EASYNCRCV = 6002,
    #[error("")]
    SRT_ETIMEOUT = 6003,
    #[error("")]
    SRT_ECONGEST = 6004,

    #[error("")]
    SRT_EPEERERR = 7000,
}
