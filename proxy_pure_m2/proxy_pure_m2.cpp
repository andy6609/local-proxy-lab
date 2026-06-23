/*
============================================================
 proxy_pure_m2  —  M2 '순수 학습용' 버전 (메인 로직만)
============================================================
 목적: M2 의 본질 = "HTTP 를 파싱해서 메시지 경계를 알고, body 를
       프레이밍(Content-Length / chunked)대로 정확히 전달" 하는 것.
       제품 군더더기(스머글링 방어, 헤더 크기 상한, recv 타임아웃,
       로깅 포맷, upstream 재사용...)는 전부 제거했다.

 [M1 과의 차이 — 가장 중요]
   M1: blind relay (바이트만 퍼나름, 경계 모름)
   M2: '파싱 루프' (헤드 파싱 -> body 를 프레이밍대로 전달 -> 반복)
   => 경계를 알아야 keep-alive(다음 요청 이어받기)와
      '요청 body 정확히 추출'(나중에 파일 업로드!)이 가능하다.

 [핵심 도구: SockReader]
   TCP 는 스트림이라 recv 한 번에 메시지가 딱 안 떨어진다.
   - 헤더가 쪼개져 오거나(부분수신)
   - body 까지 미리 읽혀버린다(over-read).
   그래서 "줄 단위 / N바이트 정확히 읽기 + 잉여 보관" 리더가 필요.

 ★ M7(파일 업로드 추출)의 직접 토대 = forwardExact / forwardChunked
   (body 가 어디서 끝나는지 알고 정확히 다루는 것)
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

#pragma comment(lib, "ws2_32.lib")

static const int LISTEN_PORT = 18080;
static const int IO_CHUNK    = 16384;


// 다 보낼 때까지 반복 (부분 전송 대비)
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
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) e--;
    s = s.substr(b, e - b);
}


// ============================================================
//  SockReader: 소켓 위의 버퍼드 리더 (M2 의 심장)
// ============================================================
class SockReader {
public:
    explicit SockReader(SOCKET s) : sock(s) {}

    // 소켓에서 더 읽어 내부 버퍼에 붙임. 끊기면 false.
    bool fill() {
        char tmp[IO_CHUNK];
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        buffer.append(tmp, (size_t)n);
        return true;
    }

    // 한 줄 읽기 (\n 기준, 끝 \r\n 제거)
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
            if (!fill()) return false;   // 줄이 아직 안 끝났는데 더 못 읽음
        }
    }

    // 정확히 n 바이트 읽어 out 에 담음 (작은 데이터용)
    bool readExact(size_t n, std::string& out) {
        while (buffer.size() - off < n) if (!fill()) return false;
        out.assign(buffer, off, n);
        off += n;
        compact();
        return true;
    }

    // ★ 정확히 n 바이트를 dest 로 스트리밍 전달 (대용량 body/파일 대비)
    bool forwardExact(size_t n, SOCKET dest) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!sendAll(dest, buffer.data() + off, avail)) return false;
                off += avail; n -= avail;
                compact();
            } else if (!fill()) return false;
        }
        return true;
    }

    // 연결 종료까지 전부 전달 (길이 정보 없는 응답용)
    bool forwardUntilClose(SOCKET dest) {
        if (off < buffer.size()) {
            if (!sendAll(dest, buffer.data() + off, buffer.size() - off)) return false;
            off = buffer.size(); compact();
        }
        char tmp[IO_CHUNK];
        int n;
        while ((n = recv(sock, tmp, sizeof(tmp), 0)) > 0)
            if (!sendAll(dest, tmp, (size_t)n)) return false;
        return true;
    }

    // ★ chunked body 를 청크 단위로 그대로 전달
    bool forwardChunked(SOCKET dest) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;          // 청크 크기(16진수) 줄
            long long sz = strtoll(line.c_str(), nullptr, 16);

            std::string sizeLine = line + "\r\n";
            if (!sendAll(dest, sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {                               // 마지막 청크 -> 빈 줄까지 전달
                std::string t;
                while (readLine(t)) {
                    std::string tl = t + "\r\n";
                    if (!sendAll(dest, tl.data(), tl.size())) return false;
                    if (t.empty()) break;
                }
                return true;
            }
            if (!forwardExact((size_t)sz, dest)) return false;  // 청크 데이터
            std::string crlf;
            if (!readExact(2, crlf)) return false;              // 데이터 뒤 CRLF
            if (!sendAll(dest, crlf.data(), crlf.size())) return false;
        }
    }

private:
    void compact() {
        if (off == buffer.size()) { buffer.clear(); off = 0; }
        else if (off > 65536)     { buffer.erase(0, off); off = 0; }
    }

    SOCKET sock;
    std::string buffer;
    size_t off = 0;
};


// ============================================================
//  HTTP 헤드 (시작줄 + 헤더 목록)
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

// 시작줄 + 헤더를 빈 줄까지 읽음
static bool readHead(SockReader& r, HttpHead& head) {
    do { if (!r.readLine(head.startLine)) return false; } while (head.startLine.empty());
    while (true) {
        std::string line;
        if (!r.readLine(line)) return false;
        if (line.empty()) break;                     // 빈 줄 = 헤더 끝
        size_t colon = line.find(':');
        if (colon == std::string::npos) return false;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        trim(name); trim(value);
        head.headers.push_back({ name, value });
    }
    return true;
}


// ============================================================
//  body 프레이밍 판정 (★ M2 의 학습 포인트)
// ============================================================
enum class BodyMode { None, Length, Chunked, UntilClose };

// 요청 body: Transfer-Encoding chunked > Content-Length > 없음
//   (제품 버전은 여기서 CL+TE 동시 = smuggling 거부. 순수판은 생략)
static BodyMode requestBodyMode(const HttpHead& h, long long& clen) {
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) { clen = strtoll(cl.c_str(), nullptr, 10); return BodyMode::Length; }
    return BodyMode::None;
}

// 응답 body: 무바디 상태(204/304/HEAD) > chunked > Content-Length > 종료까지
static BodyMode responseBodyMode(const HttpHead& h, const std::string& method, int status, long long& clen) {
    if (method == "HEAD" || status == 204 || status == 304 || (status >= 100 && status < 200))
        return BodyMode::None;
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) { clen = strtoll(cl.c_str(), nullptr, 10); return BodyMode::Length; }
    return BodyMode::UntilClose;
}


// ============================================================
//  시작줄 파서 + 유틸
// ============================================================
static bool parseRequestLine(const std::string& line, std::string& m, std::string& u, std::string& v) {
    size_t s1 = line.find(' ');               if (s1 == std::string::npos) return false;
    size_t s2 = line.find(' ', s1 + 1);       if (s2 == std::string::npos) return false;
    m = line.substr(0, s1);
    u = line.substr(s1 + 1, s2 - s1 - 1);
    v = line.substr(s2 + 1);
    return true;
}

static int parseStatus(const std::string& line) {
    size_t s = line.find(' ');
    return (s == std::string::npos) ? 0 : atoi(line.c_str() + s + 1);
}

static void splitHostPort(const std::string& hp, std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos) { host = hp.substr(0, c); port = hp.substr(c + 1); }
    else                        { host = hp; port = defPort; }
}

static bool wantsClose(const HttpHead& h) {
    return toLower(headerGet(h, "connection")).find("close") != std::string::npos;
}

static SOCKET ConnectUpstream(const std::string& host, const std::string& port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* info = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &info) != 0) return INVALID_SOCKET;
    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock != INVALID_SOCKET &&
        connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock); sock = INVALID_SOCKET;
    }
    freeaddrinfo(info);
    return sock;
}


// ============================================================
//  HandleClient: 파싱 루프 (★ M2 의 메인 흐름)
//    [요청 파싱]->[전달]->[요청body]->[응답 파싱]->[전달]->[응답body]->[반복]
// ============================================================
static void HandleClient(SOCKET clientSock) {
    SockReader client(clientSock);

    while (true) {
        // 1. 요청 헤드 파싱
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

        // 2. upstream 연결 (순수판: 요청마다 새로 연결)
        SOCKET upstream = ConnectUpstream(host, port);
        if (upstream == INVALID_SOCKET) break;
        SockReader up(upstream);

        // 3. 요청 헤드 + body 를 upstream 으로
        std::string headOut = serializeHead(req);
        if (!sendAll(upstream, headOut.data(), headOut.size())) { closesocket(upstream); break; }
        if (reqMode == BodyMode::Length)  client.forwardExact((size_t)reqLen, upstream);
        else if (reqMode == BodyMode::Chunked) client.forwardChunked(upstream);

        // 4. 응답 헤드 파싱
        HttpHead resp;
        if (!readHead(up, resp)) { closesocket(upstream); break; }
        int status = parseStatus(resp.startLine);

        // 5. 응답 헤드 + body 를 클라로
        std::string respHeadOut = serializeHead(resp);
        if (!sendAll(clientSock, respHeadOut.data(), respHeadOut.size())) { closesocket(upstream); break; }

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        bool serverClosed = false;
        if (respMode == BodyMode::Length)       up.forwardExact((size_t)respLen, clientSock);
        else if (respMode == BodyMode::Chunked) up.forwardChunked(clientSock);
        else if (respMode == BodyMode::UntilClose) { up.forwardUntilClose(clientSock); serverClosed = true; }

        printf("[http] %-6s %s%s -> %d\n", method.c_str(), host.c_str(), uri.c_str(), status);

        closesocket(upstream);

        // 6. keep-alive 판단 (close 신호 있거나 길이 모를 응답이면 종료)
        if (serverClosed || wantsClose(req) || wantsClose(resp)) break;
    }

    closesocket(clientSock);
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
    printf("[proxy_pure_m2] %d listening... (HTTP parse loop)\n", LISTEN_PORT);

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
