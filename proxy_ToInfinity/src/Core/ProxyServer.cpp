#include "Core/ProxyServer.h"
#include "Core/Logger.h"
#include "Core/Context.h"
#include "Protocol/Http1Engine.h"

#include <thread>

namespace proxy {

ProxyServer::ProxyServer(int port) : port_(port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

ProxyServer::~ProxyServer() {
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

void ProxyServer::start() {
    listenSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket_ == INVALID_SOCKET) {
        Logger::error("Failed to create listen socket");
        return;
    }

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(listenSocket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        Logger::error("Failed to bind port " + std::to_string(port_));
        closesocket(listenSocket_);
        return;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Listen failed");
        closesocket(listenSocket_);
        return;
    }

    isRunning_ = true;
    Logger::info("ProxyServer listening on port " + std::to_string(port_));

    acceptLoop();
}

void ProxyServer::stop() {
    if (isRunning_) {
        isRunning_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
        }
    }
}

void ProxyServer::acceptLoop() {
    while (isRunning_) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
        
        if (!isRunning_) break;

        if (clientSock == INVALID_SOCKET) {
            Logger::warn("Accept failed");
            continue;
        }

        // cpp-httplib의 스레드 모델 벤치마킹: 1연결 = 1스레드 분리
        std::thread([this, clientSock]() {
            handleConnection(clientSock);
        }).detach();
    }
}

void ProxyServer::handleConnection(SOCKET clientSock) {
    // 1. 소켓만 감싼 빈 Context 생성
    Context ctx;
    ctx.clientSock = clientSock;

    // 2. HTTP/1.1 엔진으로 넘겨서 CONNECT 파싱, TLS 핸드셰이크(TlsManager 사용),
    //    그리고 통신 루프까지 수행하도록 위임
    Http1Engine::process(ctx);
}

} // namespace proxy
