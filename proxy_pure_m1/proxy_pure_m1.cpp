/*
============================================================
 proxy_pure_m1  —  M1 '순수 학습용' 버전 (메인 로직만)
============================================================
 목적: 프록시의 가장 기본 = "양방향(full-duplex) 릴레이" 의 본질만.
       제품 군더더기 없이 흐름만 눈으로 따라가는 게 목표.

 핵심 한 가지:
   Relay(from, to) 를 '두 방향에 동시에'(스레드 2개) 돌린다.
   - 방향 A: 클라 -> 서버
   - 방향 B: 서버 -> 클라
   한쪽이 끊기면 shutdown 으로 반대쪽도 같이 종료.

 흐름:
   accept -> 첫 요청 recv -> Host 파싱 -> 진짜 서버 connect
          -> 첫 요청 전달 -> 양방향 릴레이 -> 정리
============================================================
*/

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <string>
#include <thread>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

static const int LISTEN_PORT = 18080;
static const int BUF_SIZE    = 16384;


// 한 방향 릴레이: 받은 만큼 그대로 전달 (내용 안 봄).
//   끝나면 shutdown(SD_SEND) -> 반대쪽 recv 도 0 받고 같이 종료.
static void Relay(SOCKET from, SOCKET to) {
    char buf[BUF_SIZE];
    int n;
    while ((n = recv(from, buf, sizeof(buf), 0)) > 0) {
        int sent = 0;
        while (sent < n) {
            int s = send(to, buf + sent, n - sent, 0);
            if (s <= 0) return;
            sent += s;
        }
    }
    shutdown(to, SD_SEND);
}


// 도메인 -> IP 변환 후 연결
static SOCKET ConnectUpstream(const std::string& host, const std::string& port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* info = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &info) != 0)
        return INVALID_SOCKET;

    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock != INVALID_SOCKET &&
        connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(info);
    return sock;
}


// "Host: xxx" 줄에서 호스트명만 뽑음
static std::string parseHostHeader(const char* req) {
    const char* p = strstr(req, "Host:");
    if (!p) return "";
    p += 5;
    while (*p == ' ') p++;
    std::string h;
    while (*p && *p != '\r' && *p != '\n' && *p != ':') h += *p++;
    return h;
}


// 연결 하나 처리
static void HandleClient(SOCKET clientSock) {
    char buf[BUF_SIZE];

    // 1. 첫 요청 받기 (목적지 Host 알아내려고)
    int n = recv(clientSock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { closesocket(clientSock); return; }
    buf[n] = '\0';

    // 2. Host 파싱
    std::string host = parseHostHeader(buf);
    if (host.empty()) { closesocket(clientSock); return; }

    // 3. 진짜 서버 연결 (:80)
    SOCKET upstream = ConnectUpstream(host, "80");
    if (upstream == INVALID_SOCKET) { closesocket(clientSock); return; }
    printf("[relay] %s\n", host.c_str());

    // 4. 이미 읽어둔 첫 요청을 먼저 전달
    send(upstream, buf, n, 0);

    // 5. 양방향 릴레이 (★ M1 의 핵심)
    std::thread t(Relay, clientSock, upstream);  // 클라 -> 서버
    Relay(upstream, clientSock);                  // 서버 -> 클라 (현재 스레드)
    t.join();                                     // 두 방향 다 끝날 때까지 대기

    // 6. 정리
    closesocket(upstream);
    closesocket(clientSock);
    printf("[relay] %s done\n", host.c_str());
}


static void RunServer() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenSock, SOMAXCONN);
    printf("[proxy_pure_m1] %d listening... (full-duplex relay)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;
        std::thread(HandleClient, clientSock).detach();
    }
}

int main() {
    RunServer();
    return 0;
}
