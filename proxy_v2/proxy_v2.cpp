/*
============================================================
 proxy_v2  —  M2: 견고한 HTTP 파싱 + keep-alive + 방어적 처리
============================================================
 execution-plan-to-mitm.md 의 M2 정의대로 '제품 수준'으로 새로 작성.

 [M1 과의 가장 큰 구조 차이]
   M1(proxy_v1) 의 Relay 는 "내용 안 보고 바이트만 퍼나르는(blind pump)" 방식이었다.
   하지만 M2 는 요청을 '파싱'하고 keep-alive 로 '메시지 경계'를 알아야 한다.
   이 둘은 양립 불가다. 한 번에 한 메시지의 경계를 알아야 다음 요청을 이어 받을 수 있기 때문.
   => 그래서 M2 의 HTTP 경로는:
        [요청 헤드 파싱] -> [upstream 전달] -> [요청 body 프레이밍대로 전달]
        -> [응답 헤드 파싱] -> [클라 전달] -> [응답 body 프레이밍대로 전달] -> [루프]
      blind relay 는 M3(CONNECT 터널)에서 다시 등장할 예정. 여기선 안 쓴다.

 [핵심 도구: SockReader (버퍼드 리더)]
   TCP 는 스트림이라 recv 한 번에 메시지가 딱 떨어져 오지 않는다.
   - 헤더가 여러 recv 에 쪼개져 올 수 있고(부분수신)
   - 반대로 헤더를 읽다가 body(혹은 다음 요청)까지 한꺼번에 읽어버릴 수도 있다(over-read).
   그래서 "줄 단위로 읽기 / N바이트 정확히 읽기"를 제공하고,
   미리 읽어둔 잉여 바이트를 내부 버퍼에 보관하는 리더가 반드시 필요하다.

 [보안/방어 요약]
   - 헤더 전체 크기 상한 (DoS 방지)
   - Content-Length 정수 오버플로우 방어
   - Content-Length + Transfer-Encoding 동시 존재 => 요청 거부 (request smuggling 방어)
   - recv 타임아웃 (멈춘 연결이 스레드를 영구 점유하지 못하게)

 [트레이드오프: 연결당 std::thread 1개]
   PoC 규모라 단순/명확함을 택했다. 대규모면 IOCP 같은 이벤트 모델이 맞다(보고서에 명시).
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
#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

// ---------------- 설정 상수 ----------------
static const int    LISTEN_PORT      = 18080;
static const size_t MAX_HEAD_BYTES   = 64 * 1024;      // 요청/응답 헤드 전체 상한 (DoS 방지)
static const long long MAX_BODY_LEN  = 1LL << 40;      // Content-Length / chunk 크기 상한(~1TB) (오버플로우/비정상 방지)
static const int    RECV_TIMEOUT_MS  = 30000;          // 멈춘 연결 정리용 idle 타임아웃
static const int    IO_CHUNK         = 16384;          // recv/send 단위

static std::mutex g_logMutex;  // 여러 스레드가 동시에 로그 찍어도 줄이 안 섞이게


// ============================================================
//  작은 문자열 유틸
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

// 모든 데이터를 다 보낼 때까지 반복 (부분 전송 대비)
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
//  SockReader: 소켓 위의 '버퍼드 리더'
//    - 줄 단위 읽기(readLine), N바이트 정확히 읽기(readExact)
//    - 미리 읽어둔(over-read) 바이트는 내부 buffer 에 보관 -> 다음 호출이 이어 씀
//    - 소켓 소유권은 갖지 않는다(닫는 건 호출자 책임). keep-alive 로 재사용하기 위함.
// ============================================================
class SockReader {
public:
    explicit SockReader(SOCKET s) : sock(s) {}

    // 소켓에서 더 읽어 내부 buffer 뒤에 붙임. EOF/에러/타임아웃이면 false.
    bool fill() {
        char tmp[IO_CHUNK];
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;       // 0=정상 종료, <0=에러/타임아웃 -> 더 못 읽음
        buffer.append(tmp, (size_t)n);
        return true;
    }

    // 한 줄 읽기('\n' 기준). 끝의 \r\n 은 제거하고 돌려줌.
    // 헤드가 MAX_HEAD_BYTES 넘게 길어지면 방어적으로 false.
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
            if (buffer.size() - off > MAX_HEAD_BYTES) return false; // 한 줄이 비정상적으로 김
            if (!fill()) return false;
        }
    }

    // 정확히 n 바이트를 out 에 담아 읽음 (작은 데이터용; body 는 forward* 로 스트리밍)
    bool readExact(size_t n, std::string& out) {
        while (buffer.size() - off < n) {
            if (!fill()) return false;
        }
        out.assign(buffer, off, n);
        off += n;
        compact();
        return true;
    }

    // 정확히 n 바이트를 dest 로 '스트리밍' 전달 (파일 업로드 같은 대용량 대비: 통째로 안 들고 흘려보냄)
    bool forwardExact(size_t n, SOCKET dest) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!sendAll(dest, buffer.data() + off, avail)) return false;
                off += avail; n -= avail;
                compact();
            } else {
                if (!fill()) return false;  // 아직 다 못 받았는데 끊김 -> 실패
            }
        }
        return true;
    }

    // upstream EOF(연결 종료)까지 전부 dest 로 전달 (응답 길이를 모를 때 = connection-close 프레이밍)
    bool forwardUntilClose(SOCKET dest) {
        if (off < buffer.size()) {
            if (!sendAll(dest, buffer.data() + off, buffer.size() - off)) return false;
            off = buffer.size(); compact();
        }
        char tmp[IO_CHUNK];
        while (true) {
            int n = recv(sock, tmp, sizeof(tmp), 0);
            if (n <= 0) break;                 // 종료 = 정상적인 body 끝
            if (!sendAll(dest, tmp, (size_t)n)) return false;
        }
        return true;
    }

    // chunked body 를 청크 단위로 그대로 dest 에 전달 (크기줄/데이터/CRLF/트레일러 보존)
    bool forwardChunked(SOCKET dest) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;          // 청크 크기 줄
            long long sz;
            if (!parseHexChunkSize(line, sz)) return false;

            std::string sizeLine = line + "\r\n";
            if (!sendAll(dest, sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {                               // 마지막 청크 -> 트레일러(빈 줄까지) 전달
                while (true) {
                    std::string t;
                    if (!readLine(t)) return false;
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
        if (off == buffer.size()) { buffer.clear(); off = 0; }      // 다 읽었으면 리셋
        else if (off > 65536)     { buffer.erase(0, off); off = 0; } // 앞쪽 잉여가 크면 정리
    }

    static bool parseHexChunkSize(const std::string& line, long long& out) {
        long long v = 0; bool any = false;
        for (char c : line) {
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;                       // ';'(확장) 이나 공백에서 멈춤
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
//  HTTP 헤드(요청/응답 공통): 시작줄 + 헤더 목록
// ============================================================
struct HttpHead {
    std::string startLine;                                   // "GET ... HTTP/1.1" 또는 "HTTP/1.1 200 OK"
    std::vector<std::pair<std::string, std::string>> headers; // 순서 보존(그대로 재전송하려고)
};

// 헤더 값 조회(이름 대소문자 무시). 첫 매치 반환, 없으면 "".
static std::string headerGet(const HttpHead& h, const std::string& lname) {
    for (const auto& kv : h.headers)
        if (toLower(kv.first) == lname) return kv.second;
    return "";
}

// 헤드를 다시 바이트로 직렬화(파싱한 걸 그대로 재전송)
static std::string serializeHead(const HttpHead& h) {
    std::string s = h.startLine + "\r\n";
    for (const auto& kv : h.headers) s += kv.first + ": " + kv.second + "\r\n";
    s += "\r\n";
    return s;
}

// 시작줄+헤더를 빈 줄까지 읽어 head 에 채움. 방어적 크기 검사 포함.
static bool readHead(SockReader& r, HttpHead& head) {
    // 요청 라인 앞의 빈 줄(일부 클라가 보냄)은 건너뜀
    do {
        if (!r.readLine(head.startLine)) return false;
    } while (head.startLine.empty());

    size_t total = head.startLine.size() + 2;
    while (true) {
        std::string line;
        if (!r.readLine(line)) return false;
        if (line.empty()) break;              // 빈 줄 = 헤더 끝
        total += line.size() + 2;
        if (total > MAX_HEAD_BYTES) return false;  // 헤드 전체 상한 초과 -> 방어적 거부

        size_t colon = line.find(':');
        if (colon == std::string::npos) return false;  // 콜론 없는 줄 = 형식 오류
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        trim(name); trim(value);
        if (name.empty()) return false;
        head.headers.push_back({ name, value });
    }
    return true;
}


// ============================================================
//  프레이밍(메시지 본문 경계) 판정
// ============================================================
enum class BodyMode { None, Length, Chunked, UntilClose, Error };

// Content-Length 파싱 + 오버플로우/형식 방어
static bool parseContentLength(const std::string& s, long long& out) {
    std::string t = s; trim(t);
    if (t.empty()) return false;
    long long v = 0;
    for (char c : t) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > MAX_BODY_LEN) return false;   // 오버플로우/비정상 크기 방어
    }
    out = v; return true;
}

// [요청] body 프레이밍 결정 + request smuggling 방어
//   - CL 과 TE 가 동시에 있으면 => Error (스머글링 방지)
//   - CL 이 여러 개인데 값이 다르면 => Error
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
    return BodyMode::None;   // 요청은 기본적으로 body 없음
}

// [응답] body 프레이밍 결정 (RFC 7230 규칙 요약)
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
    return BodyMode::UntilClose;  // 길이 정보 없음 -> 연결 종료가 곧 body 끝
}


// ============================================================
//  시작줄 파서들
// ============================================================
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

// "host" 또는 "host:port" 분리 (IPv6 대괄호는 범위 밖 - 단순 처리)
static void splitHostPort(const std::string& hp, std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos && hp.find(':', c + 1) == std::string::npos) {
        host = hp.substr(0, c);
        port = hp.substr(c + 1);
        if (port.empty()) port = defPort;
    } else {
        host = hp; port = defPort;   // 콜론 없음(또는 IPv6) -> 기본 포트
    }
}

// Connection 헤더 + 버전으로 연결 종료 여부 판단
static bool wantsClose(const HttpHead& h, const std::string& version) {
    std::string conn = toLower(headerGet(h, "connection"));
    if (conn.find("close") != std::string::npos)      return true;
    if (conn.find("keep-alive") != std::string::npos) return false;
    return (version == "HTTP/1.0");   // 1.0 기본 close, 1.1 기본 keep-alive
}


// ============================================================
//  로깅 / 간단 응답
// ============================================================
static void logLine(const std::string& method, const std::string& host,
                    const std::string& uri, int status, long long bytes) {
    time_t now = time(nullptr);
    struct tm lt; localtime_s(&lt, &now);
    char ts[16];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);

    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %-6s %s%s -> %d (%lld bytes)\n",
           ts, method.c_str(), host.c_str(), uri.c_str(), status, bytes);
}

static void logReject(const std::string& reason) {
    time_t now = time(nullptr);
    struct tm lt; localtime_s(&lt, &now);
    char ts[16];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);

    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] REJECT: %s\n", ts, reason.c_str());
}

// 최소 에러 응답 (항상 Connection: close 로 보내고 호출측이 연결 종료)
static void sendSimple(SOCKET s, const char* statusLine) {
    std::string resp = std::string("HTTP/1.1 ") + statusLine +
                       "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    sendAll(s, resp.data(), resp.size());
}


// ============================================================
//  upstream 연결
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
//  HandleClient: 한 클라 연결을 keep-alive 루프로 끝까지 처리
//    구조: [요청 파싱]->[upstream전달]->[요청body전달]
//          ->[응답 파싱]->[클라전달]->[응답body전달]->[루프]
// ============================================================
static void HandleClient(SOCKET clientSock) {
    setRecvTimeout(clientSock, RECV_TIMEOUT_MS);
    SockReader client(clientSock);

    SOCKET upstream = INVALID_SOCKET;
    std::unique_ptr<SockReader> up;       // upstream 버퍼드 리더(keep-alive 로 재사용)
    std::string curTarget;                // 현재 연결돼 있는 host:port

    while (true) {
        // --- 1. 요청 헤드 파싱 (못 읽으면 클라가 끊었거나 idle 타임아웃 -> 종료) ---
        HttpHead req;
        if (!readHead(client, req)) break;

        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) {
            sendSimple(clientSock, "400 Bad Request");
            logReject("malformed request line");
            break;
        }

        // CONNECT(HTTPS 터널)는 M3 범위 -> 여기선 미지원 명시
        if (method == "CONNECT") {
            sendSimple(clientSock, "501 Not Implemented");
            logReject("CONNECT not supported in M2");
            break;
        }

        // --- 2. 목적지(Host) ---
        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) {
            sendSimple(clientSock, "400 Bad Request");
            logReject("missing Host header");
            break;
        }
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        // --- 3. 요청 body 프레이밍 + 스머글링 방어 ---
        long long reqLen = 0;
        std::string err;
        BodyMode reqMode = requestBodyMode(req, reqLen, err);
        if (reqMode == BodyMode::Error) {
            sendSimple(clientSock, "400 Bad Request");
            logReject(err);
            break;
        }

        // --- 4. upstream 연결(같은 목적지면 재사용) ---
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

        // --- 5. 요청 헤드 + body 를 upstream 으로 전달 ---
        std::string headOut = serializeHead(req);
        if (!sendAll(upstream, headOut.data(), headOut.size())) break;

        if (reqMode == BodyMode::Length) {
            if (!client.forwardExact((size_t)reqLen, upstream)) break;
        } else if (reqMode == BodyMode::Chunked) {
            if (!client.forwardChunked(upstream)) break;
        }

        // --- 6. 응답 헤드 파싱 ---
        HttpHead resp;
        if (!readHead(*up, resp)) {
            sendSimple(clientSock, "502 Bad Gateway");
            logReject("bad upstream response head");
            break;
        }
        int status = parseStatus(resp.startLine);

        // --- 7. 응답 헤드 + body 를 클라로 전달 ---
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
            up->forwardUntilClose(clientSock);   // 길이 모름 -> 종료까지
            serverClosed = true;                 // 이 경우 keep-alive 불가
        }
        // None: body 없음

        logLine(method, host, uri, status, bodyBytes);

        // --- 8. keep-alive 판단 ---
        std::string respVer = firstToken(resp.startLine);
        if (serverClosed || wantsClose(req, version) || wantsClose(resp, respVer)) break;
    }

    // --- 정리 (자원 누수 0) ---
    if (upstream != INVALID_SOCKET) closesocket(upstream);
    closesocket(clientSock);
}


// ============================================================
//  RunServer: 18080 듣기 + 연결마다 스레드 1개
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

    // 재시작 시 "포트 사용중" 줄이기 위한 주소 재사용
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

    printf("[proxy_v2] %d listening... (HTTP parse + keep-alive)\n", LISTEN_PORT);

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
 M2 의 알려진 한계 (보고서에 기록)
============================================================
 - absolute-form URI("GET http://host/path") -> origin-form 변환 안 함.
   (지금은 받은 시작줄을 그대로 upstream 에 전달. 대부분의 서버가 수용하나 엄밀히는 변환이 맞음)
 - hop-by-hop 헤더(Connection, Proxy-Connection, Keep-Alive, TE 등) 제거/정규화 안 함.
   받은 헤더를 거의 그대로 전달한다.
 - HTTPS(CONNECT 터널) 미지원 -> M3 에서 구현.
 - HTTP/2, HTTP/3(QUIC) 미지원.
 - IPv6 host:port, Expect: 100-continue 미처리.
 - 연결당 std::thread 1개 모델(대규모 부적합; PoC 한정). 대규모면 IOCP 권장.
 - upstream keep-alive 재사용은 '직전과 같은 host:port'일 때만. 풀(pool)은 아님.
============================================================
*/
