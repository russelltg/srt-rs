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

#[repr(C)]
pub enum SRT_REJECT_REASON {
    // generic codes

    SRT_REJ_UNKNOWN = 0,     // initial set when in progress
    SRT_REJ_SYSTEM = 1,      // broken due to system function error
    SRT_REJ_PEER = 2,        // connection was rejected by peer
    SRT_REJ_RESOURCE = 3,    // internal problem with resource allocation
    SRT_REJ_ROGUE = 4,       // incorrect data in handshake messages
    SRT_REJ_BACKLOG = 5,     // listener's backlog exceeded
    SRT_REJ_IPE = 6,         // internal program error
    SRT_REJ_CLOSE = 7,       // socket is closing
    SRT_REJ_VERSION = 8,     // peer is older version than agent's minimum set
    SRT_REJ_RDVCOOKIE = 9,   // rendezvous cookie collision
    SRT_REJ_BADSECRET = 10,   // wrong password
    SRT_REJ_UNSECURE = 11,    // password required or unexpected
    SRT_REJ_MESSAGEAPI = 12,  // streamapi/messageapi collision
    SRT_REJ_CONGESTION = 13,  // incompatible congestion-controller type
    SRT_REJ_FILTER = 14,      // incompatible packet filter
    SRT_REJ_GROUP = 15,       // incompatible group
    SRT_REJ_TIMEOUT = 16,     // connection timeout
    SRT_REJ_CRYPTO = 17,      // conflicting cryptographic configurations

    // SRT-specific codes

    SRT_REJX_FALLBACK = 1000, // A code used in case when the application wants to report some problem, but can't precisely specify it.
    SRT_REJX_KEY_NOTSUP = 1001 , // The key used in the StreamID keyed string is not supported by the service.
    SRT_REJX_FILEPATH = 1002 , // The resource type designates a file and the path is either wrong syntax or not found
    SRT_REJX_HOSTNOTFOUND = 1003, // The `h` host specification was not recognized by the service

    // The list of http codes adopted for SRT.
    // An example C++ header for HTTP codes can be found at:
    // https://github.com/j-ulrich/http-status-codes-cpp

    // Some of the unused code can be revived in the future, if there
    // happens to be a good reason for it.

    SRT_REJX_BAD_REQUEST = 1400 , // General syntax error in the SocketID specification (also a fallback code for undefined cases)
    SRT_REJX_UNAUTHORIZED = 1401 , // Authentication failed, provided that the user was correctly identified and access to the required resource would be granted
    SRT_REJX_OVERLOAD = 1402 , // The server is too heavily loaded, or you have exceeded credits for accessing the service and the resource.
    SRT_REJX_FORBIDDEN = 1403 , // Access denied to the resource by any kind of reason.
    SRT_REJX_NOTFOUND = 1404 , // Resource not found at this time.
    SRT_REJX_BAD_MODE = 1405 , // The mode specified in `m` key in StreamID is not supported for this request.
    SRT_REJX_UNACCEPTABLE = 1406 , // The requested parameters specified in SocketID cannot be satisfied for the requested resource. Also when m=publish and the data format is not acceptable.
    // CODE NOT IN USE 407: unused: proxy functionality not predicted
    // CODE NOT IN USE 408: unused: no timeout predicted for listener callback
    SRT_REJX_CONFLICT = 1409 , // The resource being accessed is already locked for modification. This is in case of m=publish and the specified resource is currently read-only.
    // CODE NOT IN USE 410: unused: treated as a specific case of 404
    // CODE NOT IN USE 411: unused: no reason to include length in the protocol
    // CODE NOT IN USE 412: unused: preconditions not predicted in AC
    // CODE NOT IN USE 413: unused: AC size is already defined as 512
    // CODE NOT IN USE 414: unused: AC size is already defined as 512
    SRT_REJX_NOTSUP_MEDIA = 1415 , // The media type is not supported by the application. This is the `t` key that specifies the media type as stream, file and auth, possibly extended by the application.
    // CODE NOT IN USE 416: unused: no detailed specification defined
    // CODE NOT IN USE 417: unused: expectations not supported
    // CODE NOT IN USE 418: unused: sharks do not drink tea
    // CODE NOT IN USE 419: not defined in HTTP
    // CODE NOT IN USE 420: not defined in HTTP
    // CODE NOT IN USE 421: unused: misdirection not supported
    // CODE NOT IN USE 422: unused: aligned to general 400
    SRT_REJX_LOCKED = 1423 , // The resource being accessed is locked for any access.
    SRT_REJX_FAILED_DEPEND = 1424 , // The request failed because it specified a dependent session ID that has been disconnected.
    // CODE NOT IN USE 425: unused: replaying not supported
    // CODE NOT IN USE 426: unused: tempting, but it requires resend in connected
    // CODE NOT IN USE 427: not defined in HTTP
    // CODE NOT IN USE 428: unused: renders to 409
    // CODE NOT IN USE 429: unused: renders to 402
    // CODE NOT IN USE 451: unused: renders to 403
    SRT_REJX_ISE = 1500 , // Unexpected internal server error
    SRT_REJX_UNIMPLEMENTED = 1501 , // The request was recognized, but the current version doesn't support it.
    SRT_REJX_GW = 1502 , // The server acts as a gateway and the target endpoint rejected the connection.
    SRT_REJX_DOWN = 1503 , // The service has been temporarily taken over by a stub reporting this error. The real service can be down for maintenance or crashed.
    // CODE NOT IN USE 504: unused: timeout not supported
    SRT_REJX_VERSION = 1505 , // SRT version not supported. This might be either unsupported backward compatibility, or an upper value of a version.
    // CODE NOT IN USE 506: unused: negotiation and references not supported
    SRT_REJX_NOROOM = 1507 , // The data stream cannot be archived due to lacking storage space. This is in case when the request type was to send a file or the live stream to be archived.
    // CODE NOT IN USE 508: unused: no redirection supported
    // CODE NOT IN USE 509: not defined in HTTP
    // CODE NOT IN USE 510: unused: extensions not supported
    // CODE NOT IN USE 511: unused: intercepting proxies not supported


}
