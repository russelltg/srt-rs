#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#if defined __linux__ || defined __APPLE__
    #include <sys/socket.h>
#elif defined _WIN32 || defined WIN32
    #include <winsock2.h>
#endif


/**
 * system is unstable
 */
#define LOG_EMERG 0

/**
 * action must be taken immediately
 */
#define LOG_ALERT 1

/**
 * critical conditions
 */
#define LOG_CRIT 2

/**
 * error conditions
 */
#define LOG_ERR 3

/**
 * warning conditions
 */
#define LOG_WARNING 4

/**
 * normal but significant condition
 */
#define LOG_NOTICE 5

/**
 * informational
 */
#define LOG_INFO 6

/**
 * debug-level messages
 */
#define LOG_DEBUG 7

/**
 * Error return code
 */
#define SRT_ERROR -1

#define SRT_LIVE_DEF_PLSIZE 1316

#define SRT_SYNC_CLOCK_STDCXX_STEADY 0

#define SRT_SYNC_CLOCK_GETTIME_MONOTONIC 1

#define SRT_SYNC_CLOCK_WINQPC 2

#define SRT_SYNC_CLOCK_MACH_ABSTIME 3

#define SRT_SYNC_CLOCK_POSIX_GETTIMEOFDAY 4

#define SRT_SYNC_CLOCK_AMD64_RDTSC 5

#define SRT_SYNC_CLOCK_IA32_RDTSC 6

#define SRT_SYNC_CLOCK_IA64_ITC 7

typedef enum SRT_EPOLL_OPT {
  SRT_EPOLL_OPT_NONE = 0,
  /**
   * Ready for 'recv' operation:
   *
   * - For stream mode it means that at least 1 byte is available.
   * In this mode the buffer may extract only a part of the packet,
   * leaving next data possible for extraction later.
   *
   * - For message mode it means that there is at least one packet
   * available (this may change in future, as it is desired that
   * one full message should only wake up, not single packet of a
   * not yet extractable message).
   *
   * - For live mode it means that there's at least one packet
   * ready to play.
   *
   * - For listener sockets, this means that there is a new connection
   * waiting for pickup through the `srt_accept()` call, that is,
   * the next call to `srt_accept()` will succeed without blocking
   * (see an alias SRT_EPOLL_ACCEPT below).
   */
  SRT_EPOLL_IN = 1,
  /**
   * Ready for 'send' operation.
   *
   * - For stream mode it means that there's a free space in the
   * sender buffer for at least 1 byte of data. The next send
   * operation will only allow to send as much data as it is free
   * space in the buffer.
   *
   * - For message mode it means that there's a free space for at
   * least one UDP packet. The edge-triggered mode can be used to
   * pick up updates as the free space in the sender buffer grows.
   *
   * - For live mode it means that there's a free space for at least
   * one UDP packet. On the other hand, no readiness for OUT usually
   * means an extraordinary congestion on the link, meaning also that
   * you should immediately slow down the sending rate or you may get
   * a connection break soon.
   *
   * - For non-blocking sockets used with `srt_connect*` operation,
   * this flag simply means that the connection was established.
   */
  SRT_EPOLL_OUT = 4,
  /**
   * The socket has encountered an error in the last operation
   * and the next operation on that socket will end up with error.
   * You can retry the operation, but getting the error from it
   * is certain, so you may as well close the socket.
   */
  SRT_EPOLL_ERR = 8,
  SRT_EPOLL_UPDATE = 16,
  SRT_EPOLL_ET = (1 << 31),
} SRT_EPOLL_OPT;

typedef enum SRT_ERRNO {
  SRT_EUNKNOWN = -1,
  SRT_SUCCESS = 0,
  SRT_ECONNSETUP = 1000,
  SRT_ENOSERVER = 1001,
  SRT_ECONNREJ = 1002,
  SRT_ESOCKFAIL = 1003,
  SRT_ESECFAIL = 1004,
  SRT_ESCLOSED = 1005,
  SRT_ECONNFAIL = 2000,
  SRT_ECONNLOST = 2001,
  SRT_ENOCONN = 2002,
  SRT_ERESOURCE = 3000,
  SRT_ETHREAD = 3001,
  SRT_ENOBUF = 3002,
  SRT_ESYSOBJ = 3003,
  SRT_EFILE = 4000,
  SRT_EINVRDOFF = 4001,
  SRT_ERDPERM = 4002,
  SRT_EINVWROFF = 4003,
  SRT_EWRPERM = 4004,
  SRT_EINVOP = 5000,
  SRT_EBOUNDSOCK = 5001,
  SRT_ECONNSOCK = 5002,
  SRT_EINVPARAM = 5003,
  SRT_EINVSOCK = 5004,
  SRT_EUNBOUNDSOCK = 5005,
  SRT_ENOLISTEN = 5006,
  SRT_ERDVNOSERV = 5007,
  SRT_ERDVUNBOUND = 5008,
  SRT_EINVALMSGAPI = 5009,
  SRT_EINVALBUFFERAPI = 5010,
  SRT_EDUPLISTEN = 5011,
  SRT_ELARGEMSG = 5012,
  SRT_EINVPOLLID = 5013,
  SRT_EPOLLEMPTY = 5014,
  SRT_EBINDCONFLICT = 5015,
  SRT_EASYNCFAIL = 6000,
  SRT_EASYNCSND = 6001,
  SRT_EASYNCRCV = 6002,
  SRT_ETIMEOUT = 6003,
  SRT_ECONGEST = 6004,
  SRT_EPEERERR = 7000,
} SRT_ERRNO;

typedef enum SRT_KM_STATE {
  SRT_KM_S_UNSECURED = 0,
  SRT_KM_S_SECURING = 1,
  SRT_KM_S_SECURED = 2,
  SRT_KM_S_NOSECRET = 3,
  SRT_KM_S_BADSECRET = 4,
} SRT_KM_STATE;

typedef enum SRT_SOCKOPT {
  SRTO_MSS = 0,
  SRTO_SNDSYN = 1,
  SRTO_RCVSYN = 2,
  SRTO_ISN = 3,
  SRTO_FC = 4,
  SRTO_SNDBUF = 5,
  SRTO_RCVBUF = 6,
  SRTO_LINGER = 7,
  SRTO_UDP_SNDBUF = 8,
  SRTO_UDP_RCVBUF = 9,
  SRTO_RENDEZVOUS = 12,
  SRTO_SNDTIMEO = 13,
  SRTO_RCVTIMEO = 14,
  SRTO_REUSEADDR = 15,
  SRTO_MAXBW = 16,
  SRTO_STATE = 17,
  SRTO_EVENT = 18,
  SRTO_SNDDATA = 19,
  SRTO_RCVDATA = 20,
  SRTO_SENDER = 21,
  SRTO_TSBPDMODE = 22,
  SRTO_LATENCY = 23,
  SRTO_INPUTBW = 24,
  SRTO_OHEADBW,
  SRTO_PASSPHRASE = 26,
  SRTO_PBKEYLEN,
  SRTO_KMSTATE,
  SRTO_IPTTL = 29,
  SRTO_IPTOS,
  SRTO_TLPKTDROP = 31,
  SRTO_SNDDROPDELAY = 32,
  SRTO_NAKREPORT = 33,
  SRTO_VERSION = 34,
  SRTO_PEERVERSION,
  SRTO_CONNTIMEO = 36,
  SRTO_DRIFTTRACER = 37,
  SRTO_MININPUTBW = 38,
  SRTO_SNDKMSTATE = 40,
  SRTO_RCVKMSTATE,
  SRTO_LOSSMAXTTL,
  SRTO_RCVLATENCY,
  SRTO_PEERLATENCY,
  SRTO_MINVERSION,
  SRTO_STREAMID,
  SRTO_CONGESTION,
  SRTO_MESSAGEAPI,
  SRTO_PAYLOADSIZE,
  SRTO_TRANSTYPE = 50,
  SRTO_KMREFRESHRATE,
  SRTO_KMPREANNOUNCE,
  SRTO_ENFORCEDENCRYPTION,
  SRTO_IPV6ONLY,
  SRTO_PEERIDLETIMEO,
  SRTO_BINDTODEVICE,
  SRTO_PACKETFILTER = 60,
  SRTO_RETRANSMITALGO = 61,
  SRTO_E_SIZE,
} SRT_SOCKOPT;

typedef enum SRT_SOCKSTATUS {
  SRTS_INIT = 1,
  SRTS_OPENED,
  SRTS_LISTENING,
  SRTS_CONNECTING,
  SRTS_CONNECTED,
  SRTS_BROKEN,
  SRTS_CLOSING,
  SRTS_CLOSED,
  SRTS_NONEXIST,
} SRT_SOCKSTATUS;

typedef enum SRT_TRANSTYPE {
  SRTT_LIVE,
  SRTT_FILE,
  SRTT_INVALID,
} SRT_TRANSTYPE;

typedef int32_t SRTSOCKET;

typedef int SYSSOCKET;

typedef struct SRT_MSGCTRL {
  /**
   * Left for future
   */
  int flags;
  /**
   * TTL for a message (millisec), default -1 (no TTL limitation)
   */
  int msgttl;
  /**
   * Whether a message is allowed to supersede partially lost one. Unused in stream and live mode.
   */
  int inorder;
  /**
   * 0:mid pkt, 1(01b):end of frame, 2(11b):complete frame, 3(10b): start of frame
   */
  int boundary;
  /**
   * source time since epoch (usec), 0: use internal time (sender)
   */
  int64_t srctime;
  /**
   * sequence number of the first packet in received message (unused for sending)
   */
  int32_t pktseq;
  /**
   * message number (output value for both sending and receiving)
   */
  int32_t msgno;
  const void *grpdata;
  uintptr_t grpdata_size;
} SRT_MSGCTRL;

typedef struct SRT_TRACEBSTATS {
  int64_t msTimeStamp;
  int64_t pktSentTotal;
  int64_t pktRecvTotal;
  int pktSndLossTotal;
  int pktRcvLossTotal;
  int pktRetransTotal;
  int pktSentACKTotal;
  int pktRecvACKTotal;
  int pktSentNAKTotal;
  int pktRecvNAKTotal;
  int64_t usSndDurationTotal;
  int pktSndDropTotal;
  int pktRcvDropTotal;
  int pktRcvUndecryptTotal;
  uint64_t byteSentTotal;
  uint64_t byteRecvTotal;
  uint64_t byteRcvLossTotal;
  uint64_t byteRetransTotal;
  uint64_t byteSndDropTotal;
  uint64_t byteRcvDropTotal;
  uint64_t byteRcvUndecryptTotal;
  int64_t pktSent;
  int64_t pktRecv;
  int pktSndLoss;
  int pktRcvLoss;
  int pktRetrans;
  int pktRcvRetrans;
  int pktSentACK;
  int pktRecvACK;
  int pktSentNAK;
  int pktRecvNAK;
  double mbpsSendRate;
  double mbpsRecvRate;
  int64_t usSndDuration;
  int pktReorderDistance;
  double pktRcvAvgBelatedTime;
  int64_t pktRcvBelated;
  int pktSndDrop;
  int pktRcvDrop;
  int pktRcvUndecrypt;
  uint64_t byteSent;
  uint64_t byteRecv;
  uint64_t byteRcvLoss;
  uint64_t byteRetrans;
  uint64_t byteSndDrop;
  uint64_t byteRcvDrop;
  uint64_t byteRcvUndecrypt;
  double usPktSndPeriod;
  int pktFlowWindow;
  int pktCongestionWindow;
  int pktFlightSize;
  double msRTT;
  double mbpsBandwidth;
  int byteAvailSndBuf;
  int byteAvailRcvBuf;
  double mbpsMaxBW;
  int byteMSS;
  int pktSndBuf;
  int byteSndBuf;
  int msSndBuf;
  int msSndTsbPdDelay;
  int pktRcvBuf;
  int byteRcvBuf;
  int msRcvBuf;
  int msRcvTsbPdDelay;
  int pktSndFilterExtraTotal;
  int pktRcvFilterExtraTotal;
  int pktRcvFilterSupplyTotal;
  int pktRcvFilterLossTotal;
  int pktSndFilterExtra;
  int pktRcvFilterExtra;
  int pktRcvFilterSupply;
  int pktRcvFilterLoss;
  int pktReorderTolerance;
  int64_t pktSentUniqueTotal;
  int64_t pktRecvUniqueTotal;
  uint64_t byteSentUniqueTotal;
  uint64_t byteRecvUniqueTotal;
  int64_t pktSentUnique;
  int64_t pktRecvUnique;
  uint64_t byteSentUnique;
  uint64_t byteRecvUnique;
} SRT_TRACEBSTATS;

typedef int (*srt_listen_callback_fn)(void *opaq, SRTSOCKET ns, int, const sockaddr *peeraddr, const char *streamid);

#define SRT_INVALID_SOCK -1





#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const struct SRT_MSGCTRL srt_msgctrl_default;

int srt_startup(void);

int srt_cleanup(void);

uint32_t srt_getversion(void);

int srt_clock_type(void);

int srt_bind(SRTSOCKET sock, const sockaddr *name, int namelen);

int srt_listen(SRTSOCKET sock, int _backlog);

int srt_epoll_create(void);

/**
 * # Safety
 * * events must be null or point to a valid combination of `SRT_EPOLL_OPT` flags
 */
int srt_epoll_add_usock(int eid, SRTSOCKET sock, const int *events);

int srt_epoll_add_ssock(int eid, SYSSOCKET s, const int *events);

int srt_epoll_remove_usock(int eid, SRTSOCKET sock);

int srt_epoll_update_usock(int eid, SRTSOCKET u, const int *events);

int srt_epoll_release(int eid);

/**
 * # Safety
 * * `(r|w)num` is not null
 * * `(read|write)fds` points to a valid array of `*(r|w)num` elemens
 */
int srt_epoll_wait(int eid,
                   SRTSOCKET *readfds,
                   int *rnum,
                   SRTSOCKET *writefds,
                   int *wnum,
                   int64_t msTimeOut,
                   SYSSOCKET *lrfds,
                   int *lrnum,
                   SYSSOCKET *lwfds,
                   int *lwnum);

int srt_connect(SRTSOCKET sock, const sockaddr *name, int namelen);

SRTSOCKET srt_accept(SRTSOCKET sock, sockaddr *addr, int *addrlen);

int srt_getlasterror(int *_errno_loc);

const char *srt_getlasterror_str(void);

int srt_send(SRTSOCKET sock, const char *buf, int len);

int srt_sendmsg(SRTSOCKET sock, const char *buf, int len, int ttl, int inorder);

/**
 * Returns number of bytes written
 */
int srt_sendmsg2(SRTSOCKET sock, const char *buf, int len, const struct SRT_MSGCTRL *_mctrl);

/**
 * Returns the number of bytes read
 */
int srt_recv(SRTSOCKET sock, char *buf, int len);

int srt_recvmsg(SRTSOCKET sock, char *buf, int len);

int srt_bstats(SRTSOCKET _sock, struct SRT_TRACEBSTATS *_perf, int _clear);

SRTSOCKET srt_create_socket(void);

void srt_setloglevel(int ll);

/**
 * # Safety
 * `optval` must point to a structure of the right type depending on `optname`, according to
 * [the option documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
 */
int srt_setsockopt(SRTSOCKET sock,
                   int _level,
                   enum SRT_SOCKOPT optname,
                   const void *optval,
                   int optlen);

/**
 * # Safety
 * If `optval` is non-null, it must point to the correct datastructure
 * as specified by the [options documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
 * Additionally, `optlen` must start as the size of that datastructure
 */
int srt_getsockopt(SRTSOCKET sock,
                   int _level,
                   enum SRT_SOCKOPT optname,
                   void *optval,
                   int *optlen);

enum SRT_SOCKSTATUS srt_getsockstate(SRTSOCKET sock);

/**
 * # Safety
 * `optval` must point to a structure of the right type depending on `optname`, according to
 * [the option documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
 */
int srt_setsockflag(SRTSOCKET sock,
                    enum SRT_SOCKOPT opt,
                    const void *optval,
                    int optlen);

/**
 * # Safety
 * If `optval` is non-null, it must point to the correct datastructure
 * as specified by the [options documentation](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md)
 * Additionally, `optlen` must start as the size of that datastructure
 */
int srt_getsockflag(SRTSOCKET sock,
                    enum SRT_SOCKOPT opt,
                    void *optval,
                    int *optlen);

int srt_getsockname(SRTSOCKET _sock, sockaddr *_name, int *_namelen);

int srt_getpeername(SRTSOCKET _sock, sockaddr *_name, int *_namelen);

/**
 * # Safety
 * - `hook_fn` must contain a function pointer of the right signature
 * - `hook_fn` must be callable from another thread
 * - `hook_opaque` must live as long as the socket and be passable between threads
 */
int srt_listen_callback(SRTSOCKET sock, srt_listen_callback_fn hook_fn, void *hook_opaque);

int64_t srt_time_now(void);

int srt_close(SRTSOCKET socknum);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
