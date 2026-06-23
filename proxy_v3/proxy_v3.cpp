/*
============================================================
 proxy_v3  —  M3: HTTPS 터널 (CONNECT, raw 통과)  [+ M2 전부 포함]
============================================================
 execution-plan-to-mitm.md 의 M3 정의대로 '제품 수준'으로 작성.
 proxy_v2(M2: HTTP 파싱 + keep-alive)를 토대로, CONNECT 처리를 추가했다.
 => 이제 진짜 브라우저처럼 'HTTP' 와 'HTTPS' 둘 다 프록시 경유가 된다.

 [M3 의 핵심: blind relay 가 여기서 다시 등장]
   - M2 에서 blind relay 를 '버린' 게 아니라 'CONNECT 터널 전용으로 보류'했었다.
   - HTTPS 는 CONNECT 직후부터 'TLS 암호화 바이트'가 흐른다.
     프록시는 그걸 복호화 못 하니까(=내용 못 봄) 파싱하지 않고
     그냥 양방향으로 흘려보내야 한다. 이게 바로 M1 의 blind relay 다.
   => 정리:
        - 평문 HTTP (GET/POST...) -> M2 파싱 루프
        - HTTPS (CONNECT)         -> 200 응답 후 blind 양방향 릴레이

 [CONNECT 흐름]
   브라우저 -> 프록시 : "CONNECT example.com:443 HTTP/1.1"
   프록시 -> 진짜서버 : TCP connect(example.com:443)
   프록시 -> 브라우저 : "HTTP/1.1 200 Connection Established"
   --- 이후 ---
   브라우저 <-> 프록시 <-> 진짜서버 : TLS 암호 바이트를 그대로 양방향 통과

 [보안 포인트 - 회사 제출용]
   - CONNECT 포트 화이트리스트: 아무 포트로나 터널을 못 뚫게 제한.
     (안 막으면 프록시가 SSRF/내부 포트스캔 도구로 악용될 수 있음 - 실제 보안 이슈)

 [중요한 함정: pre-read 바이트]
   M2 의 SockReader 가 CONNECT 줄을 읽다가 그 '뒤'(=TLS ClientHello 시작)까지
   미리 읽어버렸을 수 있다. 터널 시작 전에 이 잉여 바이트를 upstream 에 먼저
   흘려보내지 않으면 handshake 가 깨진다. -> takeBuffered() 로 처리.
============================================================
*/

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

// ---------------- 설정 상수 ----------------
static const int    LISTEN_PORT      = 18080;
static const size_t MAX_HEAD_BYTES   = 64 * 1024;
static const long long MAX_BODY_LEN  = 1LL << 40;
static const int    RECV_TIMEOUT_MS  = 30000;
static const int    IO_CHUNK         = 16384;

// CONNECT 로 터널 허용할 포트(화이트리스트). 기본 HTTPS(443)만.
// 필요하면 8443 등 추가. 빈 목록이면 모두 거부.
static const int ALLOWED_CONNECT_PORTS[] = { 443 };

static std::mutex g_logMutex;


// ============================================================
//  작은 문자열/소켓 유틸
// ============================================================
static std::string toLower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static void trim(std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) b++;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) e--;
    s = s.substr(b, e - b);
}

static bool sendAll(SOCKET s, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static void setRecvTimeout(SOCKET s, int ms) {
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
}


// ============================================================
//  SockReader: 소켓 위의 버퍼드 리더 (M2 와 동일 + takeBuffered 추가)
// ============================================================
class SockReader {
public:
    explicit SockReader(SOCKET s) : sock(s) {}

    bool fill() {
        char tmp[IO_CHUNK];
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        buffer.append(tmp, (size_t)n);
        return true;
    }

    bool readLine(std::string& out) {
        while (true) {
            size_t nl = buffer.find('\n', off);
            if (nl != std::string::npos) {
                out.assign(buffer, off, nl - off);
                if (!out.empty() && out.back() == '\r') out.pop_back();
                off = nl + 1;
                compact();
                return true;
            }
            if (buffer.size() - off > MAX_HEAD_BYTES) return false;
            if (!fill()) return false;
        }
    }

    bool readExact(size_t n, std::string& out) {
        while (buffer.size() - off < n) {
            if (!fill()) return false;
        }
        out.assign(buffer, off, n);
        off += n;
        compact();
        return true;
    }

    bool forwardExact(size_t n, SOCKET dest) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!sendAll(dest, buffer.data() + off, avail)) return false;
                off += avail; n -= avail;
                compact();
            } else {
                if (!fill()) return false;
            }
        }
        return true;
    }

    bool forwardUntilClose(SOCKET dest) {
        if (off < buffer.size()) {
            if (!sendAll(dest, buffer.data() + off, buffer.size() - off)) return false;
            off = buffer.size(); compact();
        }
        char tmp[IO_CHUNK];
        while (true) {
            int n = recv(sock, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            if (!sendAll(dest, tmp, (size_t)n)) return false;
        }
        return true;
    }

    bool forwardChunked(SOCKET dest) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;
            long long sz;
            if (!parseHexChunkSize(line, sz)) return false;

            std::string sizeLine = line + "\r\n";
            if (!sendAll(dest, sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {
                while (true) {
                    std::string t;
                    if (!readLine(t)) return false;
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

    // [M3 추가] 헤드를 읽다가 미리 읽어둔(over-read) 잉여 바이트를 꺼내 비움.
    //   CONNECT 직후, 이미 들어와 있을 수 있는 TLS ClientHello 시작분을
    //   터널 upstream 으로 먼저 흘려보내기 위해 사용.
    std::string takeBuffered() {
        std::string s = buffer.substr(off);
        buffer.clear(); off = 0;
        return s;
    }

private:
    void compact() {
        if (off == buffer.size()) { buffer.clear(); off = 0; }
        else if (off > 65536)     { buffer.erase(0, off); off = 0; }
    }

    static bool parseHexChunkSize(const std::string& line, long long& out) {
        long long v = 0; bool any = false;
        for (char c : line) {
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            v = v * 16 + d; any = true;
            if (v > MAX_BODY_LEN) return false;
        }
        if (!any) return false;
        out = v; return true;
    }

    SOCKET sock;
    std::string buffer;
    size_t off = 0;
};


// ============================================================
//  HTTP 헤드 + 파서들 (M2 와 동일)
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
    do {
        if (!r.readLine(head.startLine)) return false;
    } while (head.startLine.empty());

    size_t total = head.startLine.size() + 2;
    while (true) {
        std::string line;
        if (!r.readLine(line)) return false;
        if (line.empty()) break;
        total += line.size() + 2;
        if (total > MAX_HEAD_BYTES) return false;

        size_t colon = line.find(':');
        if (colon == std::string::npos) return false;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        trim(name); trim(value);
        if (name.empty()) return false;
        head.headers.push_back({ name, value });
    }
    return true;
}

enum class BodyMode { None, Length, Chunked, UntilClose, Error };

static bool parseContentLength(const std::string& s, long long& out) {
    std::string t = s; trim(t);
    if (t.empty()) return false;
    long long v = 0;
    for (char c : t) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > MAX_BODY_LEN) return false;
    }
    out = v; return true;
}

static BodyMode requestBodyMode(const HttpHead& h, long long& clen, std::string& err) {
    bool hasCL = false, hasTE = false;
    long long cl = -1;
    std::string te;
    for (const auto& kv : h.headers) {
        std::string n = toLower(kv.first);
        if (n == "content-length") {
            long long v;
            if (!parseContentLength(kv.second, v)) { err = "bad Content-Length"; return BodyMode::Error; }
            if (hasCL && cl != v) { err = "conflicting Content-Length"; return BodyMode::Error; }
            hasCL = true; cl = v;
        } else if (n == "transfer-encoding") {
            hasTE = true; te = toLower(kv.second);
        }
    }
    if (hasCL && hasTE) { err = "Content-Length + Transfer-Encoding (smuggling)"; return BodyMode::Error; }
    if (hasTE) {
        if (te.find("chunked") != std::string::npos) return BodyMode::Chunked;
        err = "unsupported Transfer-Encoding"; return BodyMode::Error;
    }
    if (hasCL) { clen = cl; return BodyMode::Length; }
    return BodyMode::None;
}

static BodyMode responseBodyMode(const HttpHead& h, const std::string& reqMethod, int status, long long& clen) {
    if (reqMethod == "HEAD")                          return BodyMode::None;
    if ((status >= 100 && status < 200) ||
        status == 204 || status == 304)               return BodyMode::None;

    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (!te.empty() && te.find("chunked") != std::string::npos) return BodyMode::Chunked;

    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) {
        long long v;
        if (parseContentLength(cl, v)) { clen = v; return BodyMode::Length; }
    }
    return BodyMode::UntilClose;
}

static bool parseRequestLine(const std::string& line, std::string& m, std::string& u, std::string& v) {
    size_t s1 = line.find(' ');
    if (s1 == std::string::npos) return false;
    size_t s2 = line.find(' ', s1 + 1);
    if (s2 == std::string::npos) return false;
    m = line.substr(0, s1);
    u = line.substr(s1 + 1, s2 - s1 - 1);
    v = line.substr(s2 + 1);
    return !(m.empty() || u.empty() || v.empty());
}

static int parseStatus(const std::string& line) {
    size_t s1 = line.find(' ');
    if (s1 == std::string::npos) return 0;
    return atoi(line.c_str() + s1 + 1);
}

static std::string firstToken(const std::string& line) {
    size_t s = line.find(' ');
    return (s == std::string::npos) ? line : line.substr(0, s);
}

static void splitHostPort(const std::string& hp, std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos && hp.find(':', c + 1) == std::string::npos) {
        host = hp.substr(0, c);
        port = hp.substr(c + 1);
        if (port.empty()) port = defPort;
    } else {
        host = hp; port = defPort;
    }
}

static bool wantsClose(const HttpHead& h, const std::string& version) {
    std::string conn = toLower(headerGet(h, "connection"));
    if (conn.find("close") != std::string::npos)      return true;
    if (conn.find("keep-alive") != std::string::npos) return false;
    return (version == "HTTP/1.0");
}


// ============================================================
//  로깅 / 간단 응답
// ============================================================
static std::string nowStamp() {
    time_t now = time(nullptr);
    struct tm lt; localtime_s(&lt, &now);
    char ts[16];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    return ts;
}

static void logLine(const std::string& method, const std::string& host,
                    const std::string& uri, int status, long long bytes) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %-7s %s%s -> %d (%lld bytes)\n",
           nowStamp().c_str(), method.c_str(), host.c_str(), uri.c_str(), status, bytes);
}

static void logTunnel(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %s\n", nowStamp().c_str(), msg.c_str());
}

static void logReject(const std::string& reason) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] REJECT: %s\n", nowStamp().c_str(), reason.c_str());
}

static void sendSimple(SOCKET s, const char* statusLine) {
    std::string resp = std::string("HTTP/1.1 ") + statusLine +
                       "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    sendAll(s, resp.data(), resp.size());
}


// ============================================================
//  upstream 연결 (M2 와 동일)
// ============================================================
static SOCKET ConnectUpstream(const char* host, const char* port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* info = nullptr;
    if (getaddrinfo(host, port, &hints, &info) != 0) return INVALID_SOCKET;

    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(info); return INVALID_SOCKET; }

    if (connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock); freeaddrinfo(info); return INVALID_SOCKET;
    }
    freeaddrinfo(info);
    return sock;
}


// ============================================================
//  [M3] TunnelRelay: 한 방향 blind 릴레이 (내용 안 보고 바이트만)
//    - M1 의 Relay 와 동일 구조 + 전송 바이트 카운트
//    - 끝나면 shutdown(SD_SEND) 로 반대쪽도 같이 종료되게 신호
// ============================================================
static void TunnelRelay(SOCKET from, SOCKET to, std::atomic<long long>* counter) {
    char buf[IO_CHUNK];
    int n;
    while ((n = recv(from, buf, sizeof(buf), 0)) > 0) {
        if (!sendAll(to, buf, (size_t)n)) break;
        if (counter) counter->fetch_add(n);
    }
    shutdown(to, SD_SEND);
}

// CONNECT 대상 포트가 화이트리스트에 있나?
static bool isConnectPortAllowed(int port) {
    for (int p : ALLOWED_CONNECT_PORTS) if (p == port) return true;
    return false;
}

// ============================================================
//  [M3] CONNECT 처리: 200 응답 후 양방향 blind 터널
//    반환: 항상 연결 종료(터널이 끝나면 그 연결은 끝). 호출측이 return 함.
// ============================================================
static void HandleConnect(SOCKET clientSock, SockReader& client,
                          const std::string& target) {
    // 1. host:port 분리 (CONNECT 는 기본 443)
    std::string host, portStr;
    splitHostPort(target, host, portStr, "443");
    int port = atoi(portStr.c_str());

    // 2. [보안] 포트 화이트리스트 검사 (임의 포트 터널 = SSRF/포트스캔 악용 방지)
    if (!isConnectPortAllowed(port)) {
        sendSimple(clientSock, "403 Forbidden");
        logReject("CONNECT port not allowed: " + target);
        return;
    }

    // 3. 진짜 서버로 TCP 연결
    SOCKET upstream = ConnectUpstream(host.c_str(), portStr.c_str());
    if (upstream == INVALID_SOCKET) {
        sendSimple(clientSock, "502 Bad Gateway");
        logReject("CONNECT upstream failed: " + target);
        return;
    }
    setRecvTimeout(upstream, RECV_TIMEOUT_MS);

    // 4. 브라우저에 "터널 준비 완료" 응답
    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (!sendAll(clientSock, ok, strlen(ok))) {
        closesocket(upstream);
        return;
    }
    logTunnel("CONNECT " + target + " tunnel open");

    // 5. [함정 처리] CONNECT 줄 뒤에 이미 읽어둔 바이트(=TLS ClientHello 시작)가 있으면
    //    먼저 upstream 으로 흘려보낸다. 안 하면 handshake 가 깨진다.
    std::string pre = client.takeBuffered();
    std::atomic<long long> c2s{ (long long)pre.size() }, s2c{ 0 };
    if (!pre.empty()) sendAll(upstream, pre.data(), pre.size());

    // 6. 양방향 blind 릴레이 (여기서부터는 암호 바이트라 절대 파싱 안 함)
    std::thread t(TunnelRelay, clientSock, upstream, &c2s);  // 클라 -> 서버
    TunnelRelay(upstream, clientSock, &s2c);                 // 서버 -> 클라 (현재 스레드)
    t.join();

    // 7. 정리 + 로그
    closesocket(upstream);
    char msg[256];
    snprintf(msg, sizeof(msg), "CONNECT %s tunnel closed (up %lld / down %lld bytes)",
             target.c_str(), c2s.load(), s2c.load());
    logTunnel(msg);
}


// ============================================================
//  HandleClient: 한 연결 처리
//    - CONNECT  -> HandleConnect (터널, 연결 끝)
//    - 그 외     -> M2 HTTP 파싱 keep-alive 루프
// ============================================================
static void HandleClient(SOCKET clientSock) {
    setRecvTimeout(clientSock, RECV_TIMEOUT_MS);
    SockReader client(clientSock);

    SOCKET upstream = INVALID_SOCKET;
    std::unique_ptr<SockReader> up;
    std::string curTarget;

    while (true) {
        HttpHead req;
        if (!readHead(client, req)) break;

        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) {
            sendSimple(clientSock, "400 Bad Request");
            logReject("malformed request line");
            break;
        }

        // ---- [M3] CONNECT = HTTPS 터널 ----
        if (method == "CONNECT") {
            // 터널 전, 혹시 열려있던 HTTP upstream 은 정리
            if (upstream != INVALID_SOCKET) { closesocket(upstream); upstream = INVALID_SOCKET; up.reset(); }
            HandleConnect(clientSock, client, uri);  // uri = "host:port"
            closesocket(clientSock);
            return;  // 터널이 끝나면 이 연결도 끝
        }

        // ---- 이하 평문 HTTP 경로 (M2 와 동일) ----
        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) {
            sendSimple(clientSock, "400 Bad Request");
            logReject("missing Host header");
            break;
        }
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0;
        std::string err;
        BodyMode reqMode = requestBodyMode(req, reqLen, err);
        if (reqMode == BodyMode::Error) {
            sendSimple(clientSock, "400 Bad Request");
            logReject(err);
            break;
        }

        std::string target = host + ":" + port;
        if (upstream == INVALID_SOCKET || curTarget != target) {
            if (upstream != INVALID_SOCKET) closesocket(upstream);
            up.reset();
            upstream = ConnectUpstream(host.c_str(), port.c_str());
            if (upstream == INVALID_SOCKET) {
                sendSimple(clientSock, "502 Bad Gateway");
                logReject("upstream connect failed: " + target);
                break;
            }
            setRecvTimeout(upstream, RECV_TIMEOUT_MS);
            up = std::make_unique<SockReader>(upstream);
            curTarget = target;
        }

        std::string headOut = serializeHead(req);
        if (!sendAll(upstream, headOut.data(), headOut.size())) break;

        if (reqMode == BodyMode::Length) {
            if (!client.forwardExact((size_t)reqLen, upstream)) break;
        } else if (reqMode == BodyMode::Chunked) {
            if (!client.forwardChunked(upstream)) break;
        }

        HttpHead resp;
        if (!readHead(*up, resp)) {
            sendSimple(clientSock, "502 Bad Gateway");
            logReject("bad upstream response head");
            break;
        }
        int status = parseStatus(resp.startLine);

        std::string respHeadOut = serializeHead(resp);
        if (!sendAll(clientSock, respHeadOut.data(), respHeadOut.size())) break;

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        long long bodyBytes = 0;
        bool serverClosed = false;

        if (respMode == BodyMode::Length) {
            if (!up->forwardExact((size_t)respLen, clientSock)) break;
            bodyBytes = respLen;
        } else if (respMode == BodyMode::Chunked) {
            if (!up->forwardChunked(clientSock)) break;
        } else if (respMode == BodyMode::UntilClose) {
            up->forwardUntilClose(clientSock);
            serverClosed = true;
        }

        logLine(method, host, uri, status, bodyBytes);

        std::string respVer = firstToken(resp.startLine);
        if (serverClosed || wantsClose(req, version) || wantsClose(resp, respVer)) break;
    }

    if (upstream != INVALID_SOCKET) closesocket(upstream);
    closesocket(clientSock);
}


// ============================================================
//  RunServer (M2 와 동일)
// ============================================================
static void RunServer() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup(); return;
    }

    BOOL yes = TRUE;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(LISTEN_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listenSock); WSACleanup(); return;
    }
    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listenSock); WSACleanup(); return;
    }

    printf("[proxy_v3] %d listening... (HTTP parse + CONNECT tunnel)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            continue;
        }
        std::thread(HandleClient, clientSock).detach();
    }

    closesocket(listenSock);
    WSACleanup();
}

int main() {
    RunServer();
    return 0;
}


/*
============================================================
 M3 의 알려진 한계 (보고서에 기록)
============================================================
 - CONNECT 터널은 'raw 통과'다. 내용(TLS 암호 바이트)을 못 본다.
   => HTTPS 의 URL/헤더/body 를 보려면 MITM(M4~M5)이 필요. 그게 다음 단계.
 - CONNECT 포트 화이트리스트는 정적(443만). 운영용이면 설정 파일/정책화 필요.
 - 터널 양방향은 blind relay(스레드 2개). 대규모면 IOCP 가 맞음(PoC 한정).
 - (M2 한계 그대로 승계) absolute-form URI 변환, hop-by-hop 헤더 정규화,
   HTTP/2·HTTP/3, IPv6 host:port, Expect: 100-continue 미처리.
============================================================
*/
