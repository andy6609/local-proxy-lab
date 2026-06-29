/*
============================================================
 proxy_arch — HTTP 포워딩 프록시 (HTTP + HTTPS 터널)
============================================================
 [연결 흐름]
   main()
     └── RunServer()               listen 소켓 + accept 루프 + 연결당 스레드

            accept() 새 소켓
              └── HandleClient()  첫 줄 읽어서 CONNECT vs HTTP 분기
                    ├── HandleConnect()   HTTPS 터널
                    │     ConnectUpstream(:443)
                    │     → "200 Connection Established"
                    │     → Relay ×2 (양방향)   ← ★ MITM 끼어들 자리
                    │
                    └── HandleHttp()      평문 HTTP 파싱 루프
                          SockReader      TCP 스트림 버퍼드 리더
                          readHead()      시작줄 + 헤더들 파싱
                          BodyMode 판정   Content-Length / chunked / 없음
                          [요청 전달 → 응답 받기 → body 전달] 반복

 [함수/클래스 목록 — 정의 순서]
   sendAll              send 부분 전송 대비 반복
   toLower / trim       헤더 파싱 문자열 유틸
   ConnectUpstream      getaddrinfo + connect
   Relay                한 방향 바이트 전달 (내용 안 봄)
   SockReader           줄 단위 / N바이트 읽기 + over-read 보관
   HttpHead + readHead  시작줄 + 헤더 파싱
   serializeHead        헤더 → 바이트 직렬화
   BodyMode             body 길이 판정 (Content-Length / chunked / 없음)
   parseRequestLine     시작줄 파서 유틸
   parseStatus          응답 상태코드 추출
   splitHostPort        "host:port" 분리
   wantsClose           Connection: close 여부 확인
   HandleConnect        HTTPS 터널
   HandleHttp           HTTP 파싱 루프
   HandleClient         분기 진입점
   RunServer            서버 뼈대
============================================================
*/

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

static const int LISTEN_PORT = 18080;
static const int IO_CHUNK    = 16384;


// ============================================================
//  공통 유틸
// ============================================================

static bool sendAll(SOCKET s, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static std::string toLower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static void trim(std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) b++;
    while (e > b && (s[e-1] == ' ' || s[e-1] == '\t')) e--;
    s = s.substr(b, e - b);
}


// ============================================================
//  ConnectUpstream — 도메인→IP 변환 후 TCP 연결
// ============================================================
static SOCKET ConnectUpstream(const std::string& host, const std::string& port) {
    struct addrinfo hints = {};
    hints.ai_family   = AF_INET;
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


// ============================================================
//  Relay — 한 방향 바이트 전달 (내용 안 봄)
//    끊기면 shutdown(SD_SEND) → 반대쪽도 recv 0 받아 종료
// ============================================================
static void Relay(SOCKET from, SOCKET to) {
    char buf[IO_CHUNK];
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


// ============================================================
//  SockReader — TCP 스트림 위의 버퍼드 리더
//
//  recv 한 번에 HTTP 메시지가 딱 안 끊긴다:
//    - 헤더가 쪼개져 오거나 (부분 수신)
//    - body 바이트까지 미리 읽혀버리거나 (over-read)
//  "줄 단위 / N바이트 정확히 읽기 + 잉여 보관" 이 필요한 이유.
//
//  preread/prelen: 이미 recv 로 읽어둔 바이트를 초기 버퍼로 주입
// ============================================================
class SockReader {
public:
    explicit SockReader(SOCKET s) : sock(s) {}
    SockReader(SOCKET s, const char* preread, int prelen) : sock(s) {
        if (prelen > 0) internal.assign(preread, (size_t)prelen);
    }

    bool fill() {
        char tmp[IO_CHUNK];
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        internal.append(tmp, (size_t)n);
        return true;
    }

    bool readLine(std::string& out) {
        while (true) {
            size_t nl = internal.find('\n', off);
            if (nl != std::string::npos) {
                out.assign(internal, off, nl - off);
                if (!out.empty() && out.back() == '\r') out.pop_back();
                off = nl + 1;
                compact();
                return true;
            }
            if (!fill()) return false;
        }
    }

    bool readExact(size_t n, std::string& out) {
        while (internal.size() - off < n) if (!fill()) return false;
        out.assign(internal, off, n);
        off += n;
        compact();
        return true;
    }

    bool forwardExact(size_t n, SOCKET dest) {
        while (n > 0) {
            if (off < internal.size()) {
                size_t avail = (std::min)(n, internal.size() - off);
                if (!sendAll(dest, internal.data() + off, avail)) return false;
                off += avail; n -= avail;
                compact();
            } else if (!fill()) return false;
        }
        return true;
    }

    bool forwardUntilClose(SOCKET dest) {
        if (off < internal.size()) {
            if (!sendAll(dest, internal.data() + off, internal.size() - off)) return false;
            off = internal.size(); compact();
        }
        char tmp[IO_CHUNK];
        int n;
        while ((n = recv(sock, tmp, sizeof(tmp), 0)) > 0)
            if (!sendAll(dest, tmp, (size_t)n)) return false;
        return true;
    }

    bool forwardChunked(SOCKET dest) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;
            long long sz = strtoll(line.c_str(), nullptr, 16);

            std::string sizeLine = line + "\r\n";
            if (!sendAll(dest, sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {
                std::string t;
                while (readLine(t)) {
                    std::string tl = t + "\r\n";
                    if (!sendAll(dest, tl.data(), tl.size())) return false;
                    if (t.empty()) break;
                }
                return true;
            }
            if (!forwardExact((size_t)sz, dest)) return false;
            std::string crlf;
            if (!readExact(2, crlf)) return false;
            if (!sendAll(dest, crlf.data(), crlf.size())) return false;
        }
    }

private:
    void compact() {
        if (off == internal.size())  { internal.clear(); off = 0; }
        else if (off > 65536)        { internal.erase(0, off); off = 0; }
    }
    SOCKET sock;
    std::string internal;
    size_t off = 0;
};


// ============================================================
//  HttpHead — 시작줄 + 헤더 목록
// ============================================================
struct HttpHead {
    std::string startLine;
    std::vector<std::pair<std::string, std::string>> headers;
};

static std::string headerGet(const HttpHead& h, const std::string& lname) {
    for (const auto& kv : h.headers)
        if (toLower(kv.first) == lname) return kv.second;
    return "";
}

static std::string serializeHead(const HttpHead& h) {
    std::string s = h.startLine + "\r\n";
    for (const auto& kv : h.headers) s += kv.first + ": " + kv.second + "\r\n";
    s += "\r\n";
    return s;
}

static bool readHead(SockReader& r, HttpHead& head) {
    do { if (!r.readLine(head.startLine)) return false; } while (head.startLine.empty());
    while (true) {
        std::string line;
        if (!r.readLine(line)) return false;
        if (line.empty()) break;
        size_t colon = line.find(':');
        if (colon == std::string::npos) return false;
        std::string name  = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        trim(name); trim(value);
        head.headers.push_back({name, value});
    }
    return true;
}


// ============================================================
//  Body 프레이밍 판정
//
//  HTTP 는 body 길이를 두 가지 방식으로 알린다:
//    Content-Length: N        → 정확히 N 바이트
//    Transfer-Encoding: chunked → 청크 크기(16진수)별로 끊어 읽음
//    둘 다 없음               → 응답이면 연결 종료까지, 요청이면 body 없음
// ============================================================
enum class BodyMode { None, Length, Chunked, UntilClose };

static BodyMode requestBodyMode(const HttpHead& h, long long& clen) {
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) { clen = strtoll(cl.c_str(), nullptr, 10); return BodyMode::Length; }
    return BodyMode::None;
}

static BodyMode responseBodyMode(const HttpHead& h, const std::string& method,
                                 int status, long long& clen) {
    if (method == "HEAD" || status == 204 || status == 304 ||
        (status >= 100 && status < 200)) return BodyMode::None;
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) { clen = strtoll(cl.c_str(), nullptr, 10); return BodyMode::Length; }
    return BodyMode::UntilClose;
}


// ============================================================
//  파서 유틸
// ============================================================
static bool parseRequestLine(const std::string& line,
                             std::string& method, std::string& uri, std::string& version) {
    size_t s1 = line.find(' ');          if (s1 == std::string::npos) return false;
    size_t s2 = line.find(' ', s1 + 1); if (s2 == std::string::npos) return false;
    method  = line.substr(0, s1);
    uri     = line.substr(s1 + 1, s2 - s1 - 1);
    version = line.substr(s2 + 1);
    return true;
}

static int parseStatus(const std::string& line) {
    size_t s = line.find(' ');
    return (s == std::string::npos) ? 0 : atoi(line.c_str() + s + 1);
}

static void splitHostPort(const std::string& hp,
                          std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos) { host = hp.substr(0, c); port = hp.substr(c + 1); }
    else                         { host = hp; port = defPort; }
}

static bool wantsClose(const HttpHead& h) {
    return toLower(headerGet(h, "connection")).find("close") != std::string::npos;
}


// ============================================================
//  HandleConnect — HTTPS 터널
//
//  1) upstream(:443) TCP 연결
//  2) 브라우저에 "200 Connection Established" 응답
//  3) 양방향 relay (암호 바이트를 그대로 통과)
// ============================================================
static void HandleConnect(SOCKET clientSock, const std::string& target) {
    std::string host, port;
    splitHostPort(target, host, port, "443");

    SOCKET upstream = ConnectUpstream(host, port);
    if (upstream == INVALID_SOCKET) {
        const char* bad = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(clientSock, bad, (int)strlen(bad), 0);
        closesocket(clientSock);
        return;
    }

    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSock, ok, (int)strlen(ok), 0);
    printf("[tunnel] %s opened\n", target.c_str());

    // ★ MITM 끼어들 자리
    std::thread t(Relay, clientSock, upstream);
    Relay(upstream, clientSock);
    t.join();

    closesocket(upstream);
    closesocket(clientSock);
    printf("[tunnel] %s closed\n", target.c_str());
}


// ============================================================
//  HandleHttp — 평문 HTTP 파싱 루프
//
//  [요청 헤드 파싱] → [upstream 연결] → [요청 body 전달]
//  → [응답 헤드 파싱] → [응답 body 전달] → keep-alive 면 반복
// ============================================================
static void HandleHttp(SOCKET clientSock, const char* preread, int prelen) {
    SockReader client(clientSock, preread, prelen);

    while (true) {
        HttpHead req;
        if (!readHead(client, req)) break;

        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) break;

        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) break;
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0;
        BodyMode reqMode = requestBodyMode(req, reqLen);

        // Content-Type 으로 파일 업로드 가능성 1차 판별 (multipart/form-data)
        std::string ctype = toLower(headerGet(req, "content-type"));
        bool uploadHint = (ctype.find("multipart/form-data") != std::string::npos);

        SOCKET upstream = ConnectUpstream(host, port);
        if (upstream == INVALID_SOCKET) break;
        SockReader up(upstream);

        std::string headOut = serializeHead(req);
        if (!sendAll(upstream, headOut.data(), headOut.size())) { closesocket(upstream); break; }
        if      (reqMode == BodyMode::Length)  client.forwardExact((size_t)reqLen, upstream);
        else if (reqMode == BodyMode::Chunked) client.forwardChunked(upstream);

        HttpHead resp;
        if (!readHead(up, resp)) { closesocket(upstream); break; }
        int status = parseStatus(resp.startLine);

        std::string respOut = serializeHead(resp);
        if (!sendAll(clientSock, respOut.data(), respOut.size())) { closesocket(upstream); break; }

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        bool serverClosed = false;
        if      (respMode == BodyMode::Length)     up.forwardExact((size_t)respLen, clientSock);
        else if (respMode == BodyMode::Chunked)    up.forwardChunked(clientSock);
        else if (respMode == BodyMode::UntilClose) { up.forwardUntilClose(clientSock); serverClosed = true; }

        printf("[http] %-6s %s -> %d%s\n", method.c_str(), uri.c_str(),
               status, uploadHint ? "  [upload? multipart/form-data]" : "");
        closesocket(upstream);

        if (serverClosed || wantsClose(req) || wantsClose(resp)) break;
    }

    closesocket(clientSock);
}


// ============================================================
//  HandleClient — 첫 줄 메서드로 CONNECT vs 평문 분기
// ============================================================
static void HandleClient(SOCKET clientSock) {
    char buf[IO_CHUNK];
    int n = recv(clientSock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { closesocket(clientSock); return; }
    buf[n] = '\0';

    if (strncmp(buf, "CONNECT ", 8) == 0) {
        const char* sp1 = strchr(buf, ' ');
        const char* sp2 = sp1 ? strchr(sp1 + 1, ' ') : nullptr;
        if (!sp1 || !sp2) { closesocket(clientSock); return; }
        std::string target(sp1 + 1, sp2);
        HandleConnect(clientSock, target);
    } else {
        HandleHttp(clientSock, buf, n);
    }
}


// ============================================================
//  RunServer — listen 소켓 + accept 루프
// ============================================================
static void RunServer() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenSock, SOMAXCONN);
    printf("[proxy_arch] :%d  (HTTP + HTTPS tunnel)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;
        std::thread(HandleClient, clientSock).detach();
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);   // 로그 즉시 출력 (버퍼링 끄기)
    RunServer();
    return 0;
}
