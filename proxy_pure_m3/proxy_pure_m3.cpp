/*
============================================================
 proxy_pure_m3  —  M3 '순수 학습용' 버전 (메인 로직만)
============================================================
 목적: MITM(M4) 으로 가기 위해 'CONNECT 터널의 본질'만 남긴 최소 버전.
       proxy_v3 의 제품/보안 군더더기(포트 화이트리스트, 바이트 카운트,
       smuggling 방어, keep-alive, chunked, 타임아웃...)를 전부 걷어냈다.
       => 흐름을 눈으로 따라가며 "어디에 MITM 이 끼어드는지" 이해하는 게 목표.

 핵심 두 갈래:
   1) 평문 HTTP (GET/POST)  -> 받은 요청 그대로 전달 + 양방향 릴레이
   2) HTTPS (CONNECT)       -> "200" 응답 후 양방향 blind 릴레이(암호 바이트 통과)

 ★ 가장 중요한 지점:
   CONNECT 를 받아서 200 을 보낸 직후 = '터널이 열리는 순간'.
   M3 는 여기서 그냥 통과(blind)시키지만,
   M4(MITM) 는 바로 이 자리에서 '내가 직접 TLS 를 끊어' 복호화를 시작한다.
   => 아래 HandleConnect 의 [MITM 끼어들 자리] 주석을 보라.

 (학습용이라 의도적으로 단순화한 점: 부분수신/keep-alive/에러처리 최소.
  제품 버전은 proxy_v3 참고.)
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


// ------------------------------------------------------------
// Relay: 한 방향으로 바이트만 그대로 흘려보냄 (내용 안 봄 = blind)
//   recv 가 0 이하면 종료 -> shutdown 으로 반대쪽도 같이 끝나게 신호.
//   (M1 의 Relay 와 동일. 암호 바이트든 평문이든 '그냥 통과')
// ------------------------------------------------------------
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


// ------------------------------------------------------------
// 도메인 -> IP 연결 (host, port 문자열로)
// ------------------------------------------------------------
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


// ------------------------------------------------------------
// 첫 줄에서 메서드와 타겟을 뽑음.  예: "CONNECT example.com:443 HTTP/1.1"
//   -> method="CONNECT", target="example.com:443"
// ------------------------------------------------------------
static void parseFirstLine(const char* req, std::string& method, std::string& target) {
    const char* sp1 = strchr(req, ' ');
    if (!sp1) return;
    method.assign(req, sp1 - req);
    const char* start = sp1 + 1;
    const char* sp2 = strchr(start, ' ');
    if (!sp2) return;
    target.assign(start, sp2 - start);
}

// "Host: xxx" 한 줄에서 호스트명만 뽑음 (평문 HTTP 용)
static std::string parseHostHeader(const char* req) {
    const char* p = strstr(req, "Host:");
    if (!p) return "";
    p += 5;
    while (*p == ' ') p++;
    std::string h;
    while (*p && *p != '\r' && *p != '\n' && *p != ':') h += *p++;
    return h;
}

// "host:port" 분리 (없으면 defPort)
static void splitHostPort(const std::string& hp, std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos) { host = hp.substr(0, c); port = hp.substr(c + 1); }
    else                        { host = hp; port = defPort; }
}


// ============================================================
//  [HTTPS] CONNECT 터널 처리  ★ MITM 이 끼어들 자리가 여기다
// ============================================================
static void HandleConnect(SOCKET clientSock, const std::string& target) {
    std::string host, port;
    splitHostPort(target, host, port, "443");

    // 1. 진짜 서버로 TCP 연결
    SOCKET upstream = ConnectUpstream(host, port);
    if (upstream == INVALID_SOCKET) {
        const char* bad = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(clientSock, bad, (int)strlen(bad), 0);
        return;
    }

    // 2. 브라우저에 "터널 준비 완료" 응답
    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSock, ok, (int)strlen(ok), 0);
    printf("[tunnel] %s 열림\n", target.c_str());

    // ============================================================
    //  ★★★ [M4 MITM 끼어들 자리] ★★★
    //  지금(M3)은 여기서 그냥 양방향 blind 릴레이로 '통과'시킨다.
    //  M4(MITM)에서는 이 자리에서:
    //    - clientSock 에 대해 '가짜 인증서'로 내가 TLS 서버가 되어 handshake
    //    - upstream 에 대해 내가 TLS 클라이언트가 되어 handshake
    //    - 그 사이에서 복호화 -> 평문 HTTP -> 분석 -> 재암호화
    //  즉 아래 두 줄(blind relay) 대신, TLS 복호화 파이프라인이 들어온다.
    // ============================================================
    std::thread t(Relay, clientSock, upstream);  // 클라 -> 서버
    Relay(upstream, clientSock);                  // 서버 -> 클라
    t.join();

    closesocket(upstream);
    printf("[tunnel] %s 닫힘\n", target.c_str());
}


// ============================================================
//  [평문 HTTP] 그냥 받아서 전달 + 양방향 릴레이
// ============================================================
static void HandleHttp(SOCKET clientSock, const char* firstBuf, int firstLen) {
    std::string host = parseHostHeader(firstBuf);
    if (host.empty()) { closesocket(clientSock); return; }

    SOCKET upstream = ConnectUpstream(host, "80");
    if (upstream == INVALID_SOCKET) { closesocket(clientSock); return; }
    printf("[http] %s 중계\n", host.c_str());

    // 이미 읽어둔 첫 요청을 먼저 전달
    send(upstream, firstBuf, firstLen, 0);

    // 이후 양방향 릴레이 (keep-alive/업로드 대비, M1 과 동일)
    std::thread t(Relay, clientSock, upstream);
    Relay(upstream, clientSock);
    t.join();

    closesocket(upstream);
}


// ============================================================
//  연결 하나 처리: 첫 요청을 읽고 CONNECT 인지 평문인지 가른다
// ============================================================
static void HandleClient(SOCKET clientSock) {
    char buf[BUF_SIZE];
    int n = recv(clientSock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { closesocket(clientSock); return; }
    buf[n] = '\0';

    std::string method, target;
    parseFirstLine(buf, method, target);

    if (method == "CONNECT") {
        HandleConnect(clientSock, target);   // HTTPS 터널
    } else {
        HandleHttp(clientSock, buf, n);      // 평문 HTTP
    }
    closesocket(clientSock);
}


// ============================================================
//  서버 셋업 + accept 루프
// ============================================================
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
    printf("[proxy_pure_m3] %d listening... (HTTP + CONNECT tunnel)\n", LISTEN_PORT);

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
