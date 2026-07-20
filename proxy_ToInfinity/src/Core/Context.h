#ifndef PROXY_CONTEXT_H
#define PROXY_CONTEXT_H

#include <string>
#include <winsock2.h>
#include <openssl/ssl.h>

namespace proxy {

// 클라이언트와 업스트림 서버 간의 하나의 TCP/TLS 연결 상태를 담는 객체
struct Context {
    SOCKET clientSock = INVALID_SOCKET;
    SOCKET upstreamSock = INVALID_SOCKET;
    
    SSL* clientSsl = nullptr;
    SSL* upstreamSsl = nullptr;

    std::string targetHost;
    int targetPort = 443;
    
    // ALPN 협상 결과
    bool isClientHttp2 = false;
    bool isUpstreamHttp2 = false;
    
    ~Context() {
        // 자원 누수 방지 (RAII)
        if (clientSsl) SSL_free(clientSsl);
        if (upstreamSsl) SSL_free(upstreamSsl);
        if (clientSock != INVALID_SOCKET) closesocket(clientSock);
        if (upstreamSock != INVALID_SOCKET) closesocket(upstreamSock);
    }
};

} // namespace proxy

#endif // PROXY_CONTEXT_H
