#if defined __linux__ || defined __APPLE__
#include <sys/socket.h>
#elif defined _WIN32 || defined WIN32
#include <winsock2.h>
#endif

using SRTSOCKET = int;

typedef int (*srt_listen_callback_fn)(void* opaq, SRTSOCKET ns, int,
                                      const sockaddr* peeraddr,
                                      const char* streamid);

extern "C" int call_callback_wrap_exception(srt_listen_callback_fn fn,
                                            void* opaq, SRTSOCKET ns,
                                            int hsversion,
                                            const sockaddr* peeraddr,
                                            const char* streamid, int* ret) {
  try {
    *ret = fn(opaq, ns, hsversion, peeraddr, streamid);
  } catch (...) {
    return 1;
  }
  return 0;
}
