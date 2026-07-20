#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include <atomic>
#include <winsock2.h>

namespace proxy {

class ProxyServer {
public:
    ProxyServer(int port);
    ~ProxyServer();

    // 서버 시작 (메인 스레드 블로킹)
    void start();
    
    // 서버 종료
    void stop();

private:
    void acceptLoop();
    void handleConnection(SOCKET clientSock);

    int port_;
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::atomic<bool> isRunning_{false};
};

} // namespace proxy

#endif // PROXY_SERVER_H
