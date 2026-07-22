#ifndef PROXY_PLATFORM_H
#define PROXY_PLATFORM_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    typedef int socklen_t;
    // Windows 에서는 closesocket 사용 (그대로 유지)
#else
    // POSIX 계열 (Mac, Linux) 호환성 매핑
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
    
    // Windows 타입 매핑
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket(s) close(s)
#endif

namespace proxy {
    // 논블로킹 소켓 설정 유틸리티 (크로스 플랫폼)
    inline void setNonBlockingPlatform(SOCKET s) {
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
#else
        int flags = fcntl(s, F_GETFL, 0);
        if (flags != -1) {
            fcntl(s, F_SETFL, flags | O_NONBLOCK);
        }
#endif
    }
} // namespace proxy

#endif // PROXY_PLATFORM_H
