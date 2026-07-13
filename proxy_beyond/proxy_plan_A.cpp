/*
============================================================
 proxy_plan_A  —  proxy_v4(MITM) + Plan A
============================================================
 근거 문서: docs/scope-and-protocol-coverage.md (§2 Plan A, §3 식별 커버리지)

 [proxy_v4 대비 Plan A 가 더한 것 — 딱 3가지]
   1) ALPN 으로 HTTP/2 를 http/1.1 로 눌러 앉힘 (다운그레이드)
        - 세션1(브라우저↔프록시): SSL_CTX_set_alpn_select_cb → 무조건 "http/1.1" 선택
        - 세션2(프록시↔진짜서버): SSL_set_alpn_protos → "http/1.1" 만 광고
      => 실브라우저(크롬/엣지, 기본 h2)를 붙여도 양쪽이 1.1 로 서고,
         기존 HTTP/1.1 파서가 복호화 평문을 전부 처리한다.
      => [의도된 한계] gRPC/h2-only 클라는 1.1 제안을 거부 → handshake 실패. (Plan B(nghttp2)에서 해소)
   2) Fiddler 급 트래픽 가시화
        - 요청/응답의 '전체 헤더' 를 평문으로 덤프 (SHOW_FULL_HEADERS)
   3) 파일 업로드 식별 시작 (7주차 씨앗)
        - multipart/form-data 감지 → boundary 추출 → 요청 body 를 캡처(상한선)하며 전달
        - 캡처에서 Content-Disposition 의 name/filename, part 별 Content-Type 추출 → "FILE UPLOAD" 로그

 [빌드/설정] proxy_v4 와 동일. rootCA.crt/key 준비 + OS 신뢰 등록.
   자세힌 docs/m4-mitm-setup.md 참고. (OpenSSL 개발 라이브러리 필요)
============================================================
*/

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <map>
#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

// ---------------- 설정 상수 ----------------
static const int    LISTEN_PORT      = 18080;
static const size_t MAX_HEAD_BYTES   = 64 * 1024;
static const long long MAX_BODY_LEN  = 1LL << 40;
static const int    RECV_TIMEOUT_MS  = 30000;
static const int    IO_CHUNK         = 16384;

// Plan A: 트래픽 가시화 / 업로드 식별 스위치
static const bool   SHOW_FULL_HEADERS   = true;          // Fiddler 급 전체 헤더 덤프
static const size_t UPLOAD_CAPTURE_CAP   = 256 * 1024;   // 업로드 body 캡처 상한(식별용, 메모리 보호)

static const int ALLOWED_CONNECT_PORTS[] = { 443 };

static const char* ROOT_CA_CERT = "rootCA.crt";
static const char* ROOT_CA_KEY  = "rootCA.key";

static std::mutex g_logMutex;


// ============================================================
//  작은 유틸
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
static void setRecvTimeout(SOCKET s, int ms) {
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
}


// ============================================================
//  Stream: 입출력 추상화 (평문 소켓 / 복호화된 TLS 공통)
// ============================================================
class Stream {
public:
    virtual ~Stream() {}
    virtual int  read(char* buf, int len) = 0;          // <=0 이면 종료/에러
    virtual bool writeAll(const char* data, size_t len) = 0;
};

class SockStream : public Stream {
public:
    explicit SockStream(SOCKET s) : sock(s) {}
    int read(char* buf, int len) override { return recv(sock, buf, len, 0); }
    bool writeAll(const char* data, size_t len) override {
        size_t sent = 0;
        while (sent < len) {
            int n = send(sock, data + sent, (int)(len - sent), 0);
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }
private:
    SOCKET sock;
};

class TlsStream : public Stream {
public:
    explicit TlsStream(SSL* s) : ssl(s) {}
    int read(char* buf, int len) override { return SSL_read(ssl, buf, len); }
    bool writeAll(const char* data, size_t len) override {
        size_t sent = 0;
        while (sent < len) {
            int n = SSL_write(ssl, data + sent, (int)(len - sent));
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }
private:
    SSL* ssl;
};


// ============================================================
//  SockReader: Stream 위의 버퍼드 리더
//    forwardExact / forwardChunked 에 옵션 캡처버퍼 추가(Plan A 업로드 식별용)
// ============================================================
class SockReader {
public:
    explicit SockReader(Stream* s) : src(s) {}

    bool fill() {
        char tmp[IO_CHUNK];
        int n = src->read(tmp, sizeof(tmp));
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

    // cap != nullptr 이면 전달하는 바이트를 상한(UPLOAD_CAPTURE_CAP)까지 캡처.
    bool forwardExact(size_t n, Stream* dest, std::string* cap = nullptr) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!dest->writeAll(buffer.data() + off, avail)) return false;
                if (cap && cap->size() < UPLOAD_CAPTURE_CAP)
                    cap->append(buffer.data() + off,
                                (std::min)(avail, UPLOAD_CAPTURE_CAP - cap->size()));
                off += avail; n -= avail;
                compact();
            } else {
                if (!fill()) return false;
            }
        }
        return true;
    }

    bool forwardUntilClose(Stream* dest) {
        if (off < buffer.size()) {
            if (!dest->writeAll(buffer.data() + off, buffer.size() - off)) return false;
            off = buffer.size(); compact();
        }
        char tmp[IO_CHUNK];
        while (true) {
            int n = src->read(tmp, sizeof(tmp));
            if (n <= 0) break;
            if (!dest->writeAll(tmp, (size_t)n)) return false;
        }
        return true;
    }

    std::string takeBuffered() {
        std::string s = buffer.substr(off);
        buffer.clear(); off = 0;
        return s;
    }

    // chunked 를 그대로 전달. cap 이 있으면 '디청크된 실제 body 바이트'만 캡처.
    bool forwardChunked(Stream* dest, std::string* cap = nullptr) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;
            long long sz;
            if (!parseHexChunkSize(line, sz)) return false;

            std::string sizeLine = line + "\r\n";
            if (!dest->writeAll(sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {
                while (true) {
                    std::string t;
                    if (!readLine(t)) return false;
                    std::string tl = t + "\r\n";
                    if (!dest->writeAll(tl.data(), tl.size())) return false;
                    if (t.empty()) break;
                }
                return true;
            }
            if (!forwardExact((size_t)sz, dest, cap)) return false;   // 캡처는 body 데이터에만
            std::string crlf;
            if (!readExact(2, crlf)) return false;
            if (!dest->writeAll(crlf.data(), crlf.size())) return false;
        }
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

    Stream* src;
    std::string buffer;
    size_t off = 0;
};


// ============================================================
//  HTTP 헤드 + 파서들 (proxy_v4 와 동일)
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
//  로깅
// ============================================================
static std::string nowStamp() {
    time_t now = time(nullptr);
    struct tm lt; localtime_s(&lt, &now);
    char ts[16];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    return ts;
}
static void logLine(const char* tag, const std::string& method, const std::string& host,
                    const std::string& uri, int status, long long bytes) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %-5s %-7s %s%s -> %d (%lld bytes)\n",
           nowStamp().c_str(), tag, method.c_str(), host.c_str(), uri.c_str(), status, bytes);
}
static void logMsg(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %s\n", nowStamp().c_str(), msg.c_str());
}
static void sendRawSimple(SOCKET s, const char* statusLine) {
    std::string resp = std::string("HTTP/1.1 ") + statusLine +
                       "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    SockStream ss(s);
    ss.writeAll(resp.data(), resp.size());
}

// ---- Plan A: Fiddler 급 헤더 덤프 + 업로드 식별 ----

// 요청 전체 헤더를 평문으로 (한 블록으로 잠금 하에 출력)
static void dumpRequestView(const char* tag, const HttpHead& req,
                            const std::string& host, const std::string& uri) {
    if (!SHOW_FULL_HEADERS) return;
    std::string b;
    b += "\n===== [" + std::string(tag) + "] >> REQUEST  " + host + uri + " =====\n";
    b += req.startLine + "\n";
    for (const auto& kv : req.headers) b += "  " + kv.first + ": " + kv.second + "\n";
    std::lock_guard<std::mutex> lock(g_logMutex);
    fputs(b.c_str(), stdout);
}
static void dumpResponseView(const char* tag, const HttpHead& resp, int status) {
    if (!SHOW_FULL_HEADERS) return;
    std::string b;
    b += "----- [" + std::string(tag) + "] << RESPONSE  (" + std::to_string(status) + ") -----\n";
    b += resp.startLine + "\n";
    for (const auto& kv : resp.headers) b += "  " + kv.first + ": " + kv.second + "\n";
    std::lock_guard<std::mutex> lock(g_logMutex);
    fputs(b.c_str(), stdout);
}

// Content-Type 에서 boundary= 값을 뽑는다.
static std::string extractBoundary(const std::string& contentType) {
    std::string low = toLower(contentType);
    size_t p = low.find("boundary=");
    if (p == std::string::npos) return "";
    std::string b = contentType.substr(p + 9);
    trim(b);
    if (!b.empty() && b.front() == '"') {
        b.erase(0, 1);
        size_t q = b.find('"');
        if (q != std::string::npos) b = b.substr(0, q);
    } else {
        size_t sc = b.find(';');
        if (sc != std::string::npos) b = b.substr(0, sc);
        trim(b);
    }
    return b;
}
// 한 줄에서 key="value" 또는 key=value 를 뽑는다. (name= / filename=)
static std::string extractParam(const std::string& line, const std::string& key) {
    std::string low = toLower(line);
    size_t p = low.find(key);
    if (p == std::string::npos) return "";
    p += key.size();
    if (p < line.size() && line[p] == '"') {
        size_t q = line.find('"', p + 1);
        return line.substr(p + 1, (q == std::string::npos ? line.size() : q) - (p + 1));
    }
    size_t e = line.find_first_of("; \t", p);
    return line.substr(p, (e == std::string::npos ? line.size() : e) - p);
}

struct UploadPart { std::string field; std::string filename; std::string partType; };

// 캡처된 multipart body 에서 filename 이 있는 part 들을 뽑는다. (7주차 씨앗)
static std::vector<UploadPart> scanMultipart(const std::string& body) {
    std::vector<UploadPart> parts;
    std::string low = toLower(body);
    size_t pos = 0;
    while (true) {
        size_t d = low.find("content-disposition:", pos);
        if (d == std::string::npos) break;
        size_t eol = body.find("\r\n", d);
        std::string line = body.substr(d, (eol == std::string::npos ? body.size() : eol) - d);

        UploadPart part;
        part.field    = extractParam(line, "name=");
        part.filename = extractParam(line, "filename=");
        if (!part.filename.empty()) {
            // 같은 part 안(다음 Content-Disposition 전)의 Content-Type 을 찾는다.
            size_t nextDisp = low.find("content-disposition:", d + 1);
            size_t ct = low.find("content-type:", d);
            if (ct != std::string::npos && (nextDisp == std::string::npos || ct < nextDisp)) {
                size_t cteol = body.find("\r\n", ct);
                part.partType = body.substr(ct + 13, (cteol == std::string::npos ? body.size() : cteol) - (ct + 13));
                trim(part.partType);
            }
            parts.push_back(part);
        }
        pos = d + 1;
    }
    return parts;
}

// 업로드 여부 판정 + 로그. (multipart 인 경우만 body 캡처를 원함)
static bool isUploadRequest(const std::string& method, const HttpHead& req, std::string& boundaryOut) {
    if (method != "POST" && method != "PUT" && method != "PATCH") return false;
    std::string ct = headerGet(req, "content-type");
    if (toLower(ct).find("multipart/form-data") == std::string::npos) return false;
    boundaryOut = extractBoundary(ct);
    return true;
}
static void logUpload(const char* tag, const std::string& host, const std::string& uri,
                      const std::string& boundary, const std::string& bodyCap, long long declaredLen) {
    std::vector<UploadPart> parts = scanMultipart(bodyCap);
    bool truncated = (bodyCap.size() >= UPLOAD_CAPTURE_CAP) &&
                     (declaredLen < 0 || declaredLen > (long long)UPLOAD_CAPTURE_CAP);

    std::string b;
    b += "  *** FILE UPLOAD DETECTED [" + std::string(tag) + "]  " + host + uri + "\n";
    b += "      multipart/form-data; boundary=" + boundary + "\n";
    if (parts.empty()) {
        b += "      (no filename part found in captured " + std::to_string(bodyCap.size()) +
             " bytes" + (truncated ? ", TRUNCATED" : "") + ")\n";
    } else {
        for (const auto& p : parts) {
            b += "      - field=\"" + p.field + "\" filename=\"" + p.filename + "\"";
            if (!p.partType.empty()) b += " type=\"" + p.partType + "\"";
            b += "\n";
        }
        if (truncated) b += "      (capture TRUNCATED at " + std::to_string(UPLOAD_CAPTURE_CAP) +
                            " bytes — 뒤쪽 part 는 놓칠 수 있음)\n";
    }
    std::lock_guard<std::mutex> lock(g_logMutex);
    fputs(b.c_str(), stdout);
}


// ============================================================
//  upstream TCP 연결
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
//  [Plan A] ALPN: h2 를 http/1.1 로 강제
// ============================================================
static const unsigned char ALPN_HTTP11[] = { 8, 'h','t','t','p','/','1','.','1' };

// 세션1(서버役) 콜백: 클라가 뭘 제안하든 http/1.1 만 고른다.
static int alpnSelectHttp11(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                            const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    if (SSL_select_next_proto((unsigned char**)out, outlen,
                              ALPN_HTTP11, sizeof(ALPN_HTTP11), in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    // 클라가 http/1.1 을 아예 제안 안 함(h2-only, gRPC 등) → 다운그레이드 불가 → handshake 실패.
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}


// ============================================================
//  [MITM 인프라 1] Root CA 로딩 + host 별 leaf 인증서 동적 생성/캐시
// ============================================================
class CertAuthority {
public:
    bool load(const char* caCertPath, const char* caKeyPath) {
        BIO* bc = BIO_new_file(caCertPath, "rb");
        if (!bc) { logMsg(std::string("CA cert open fail: ") + caCertPath); return false; }
        caCert_ = PEM_read_bio_X509(bc, nullptr, nullptr, nullptr);
        BIO_free(bc);

        BIO* bk = BIO_new_file(caKeyPath, "rb");
        if (!bk) { logMsg(std::string("CA key open fail: ") + caKeyPath); return false; }
        caKey_ = PEM_read_bio_PrivateKey(bk, nullptr, nullptr, nullptr);
        BIO_free(bk);

        if (!caCert_ || !caKey_) { logMsg("CA cert/key parse fail"); return false; }

        leafKey_ = EVP_RSA_gen(2048);
        if (!leafKey_) { logMsg("leaf key gen fail"); return false; }
        return true;
    }

    SSL_CTX* serverCtxForHost(const std::string& host) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = cache_.find(host);
            if (it != cache_.end()) return it->second;
        }
        X509* leaf = makeLeaf(host);
        if (!leaf) return nullptr;

        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) { X509_free(leaf); return nullptr; }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_alpn_select_cb(ctx, alpnSelectHttp11, nullptr);   // ★ Plan A: 세션1 ALPN → http/1.1
        if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, leafKey_) != 1 ||
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(caCert_)) != 1) {
            logMsg("server ctx cert setup fail for " + host);
            X509_free(leaf); SSL_CTX_free(ctx); return nullptr;
        }
        X509_free(leaf);

        std::lock_guard<std::mutex> lk(mtx_);
        auto it = cache_.find(host);
        if (it != cache_.end()) { SSL_CTX_free(ctx); return it->second; }
        cache_[host] = ctx;
        return ctx;
    }

private:
    X509* makeLeaf(const std::string& host) {
        X509* x = X509_new();
        if (!x) return nullptr;

        X509_set_version(x, 2);

        unsigned char serial[8];
        RAND_bytes(serial, sizeof(serial));
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
        BN_free(bn);

        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x),  60L*60*24*825);

        X509_set_pubkey(x, leafKey_);

        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char*)host.c_str(), -1, -1, 0);
        X509_set_issuer_name(x, X509_get_subject_name(caCert_));

        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, caCert_, x, nullptr, nullptr, 0);
        std::string san = "DNS:" + host;
        addExt(x, &ctx, NID_subject_alt_name, san.c_str());
        addExt(x, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        addExt(x, &ctx, NID_ext_key_usage, "serverAuth");
        addExt(x, &ctx, NID_subject_key_identifier, "hash");
        addExt(x, &ctx, NID_authority_key_identifier, "keyid,issuer");

        if (X509_sign(x, caKey_, EVP_sha256()) == 0) {
            logMsg("leaf sign fail for " + host);
            X509_free(x); return nullptr;
        }
        return x;
    }
    static void addExt(X509* x, X509V3_CTX* ctx, int nid, const char* value) {
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
        if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    }

    X509*      caCert_  = nullptr;
    EVP_PKEY*  caKey_   = nullptr;
    EVP_PKEY*  leafKey_ = nullptr;
    std::mutex mtx_;
    std::map<std::string, SSL_CTX*> cache_;
};

static CertAuthority g_ca;
static SSL_CTX*      g_clientCtx = nullptr;


// ============================================================
//  [MITM 인프라 2] pre-read 바이트를 SSL_accept 에 선주입하는 커스텀 BIO
// ============================================================
struct PrefixBioData {
    SOCKET sock;
    std::string prefix;
    size_t off;
};
static int prefixBioRead(BIO* b, char* out, int len) {
    PrefixBioData* d = (PrefixBioData*)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (d->off < d->prefix.size()) {
        int n = (std::min)(len, (int)(d->prefix.size() - d->off));
        memcpy(out, d->prefix.data() + d->off, n);
        d->off += (size_t)n;
        return n;
    }
    int n = recv(d->sock, out, len, 0);
    if (n == 0) return 0;
    if (n < 0) { BIO_set_retry_read(b); return -1; }
    return n;
}
static int prefixBioWrite(BIO* b, const char* in, int len) {
    PrefixBioData* d = (PrefixBioData*)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    int sent = 0;
    while (sent < len) {
        int n = send(d->sock, in + sent, len - sent, 0);
        if (n <= 0) { if (sent) return sent; BIO_set_retry_write(b); return -1; }
        sent += n;
    }
    return sent;
}
static long prefixBioCtrl(BIO*, int cmd, long, void*) {
    return (cmd == BIO_CTRL_FLUSH) ? 1 : 0;
}
static BIO_METHOD* makePrefixBioMethod() {
    BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "prefix-sock");
    BIO_meth_set_read(m, prefixBioRead);
    BIO_meth_set_write(m, prefixBioWrite);
    BIO_meth_set_ctrl(m, prefixBioCtrl);
    return m;
}
static BIO_METHOD* g_prefixBioMethod = nullptr;


// ============================================================
//  [MITM 인프라 3] 복호화 평문 1회 교환 (Plan A: 헤더 덤프 + 업로드 식별)
// ============================================================
static bool proxyExchange(const char* tag,
                          SockReader& cr, Stream* cOut,
                          SockReader& ur, Stream* uOut,
                          const std::string& host,
                          bool& closeAfter) {
    closeAfter = true;

    // 1. 요청 헤드 (복호화된 평문)
    HttpHead req;
    if (!readHead(cr, req)) return false;

    std::string method, uri, version;
    if (!parseRequestLine(req.startLine, method, uri, version)) return false;

    long long reqLen = 0; std::string err;
    BodyMode reqMode = requestBodyMode(req, reqLen, err);
    if (reqMode == BodyMode::Error) { logMsg(std::string("REJECT: ") + err); return false; }

    dumpRequestView(tag, req, host, uri);                      // ★ Fiddler 급 요청 덤프

    // 업로드면 body 캡처
    std::string boundary;
    bool upload = isUploadRequest(method, req, boundary);
    std::string bodyCap;
    std::string* capPtr = upload ? &bodyCap : nullptr;

    // 2. 요청을 upstream 으로 전달 (+ 업로드면 캡처)
    std::string headOut = serializeHead(req);
    if (!uOut->writeAll(headOut.data(), headOut.size())) return false;
    if (reqMode == BodyMode::Length)  { if (!cr.forwardExact((size_t)reqLen, uOut, capPtr)) return false; }
    else if (reqMode == BodyMode::Chunked) { if (!cr.forwardChunked(uOut, capPtr)) return false; }

    if (upload) logUpload(tag, host, uri, boundary, bodyCap,
                          reqMode == BodyMode::Length ? reqLen : -1);   // ★ 업로드 식별

    // 3. 응답 헤드
    HttpHead resp;
    if (!readHead(ur, resp)) return false;
    int status = parseStatus(resp.startLine);

    dumpResponseView(tag, resp, status);                       // ★ Fiddler 급 응답 덤프

    // 4. 응답을 client 로 전달
    std::string respHeadOut = serializeHead(resp);
    if (!cOut->writeAll(respHeadOut.data(), respHeadOut.size())) return false;

    long long respLen = 0;
    BodyMode respMode = responseBodyMode(resp, method, status, respLen);
    long long bodyBytes = 0;
    bool serverClosed = false;
    if (respMode == BodyMode::Length) {
        if (!ur.forwardExact((size_t)respLen, cOut)) return false;
        bodyBytes = respLen;
    } else if (respMode == BodyMode::Chunked) {
        if (!ur.forwardChunked(cOut)) return false;
    } else if (respMode == BodyMode::UntilClose) {
        ur.forwardUntilClose(cOut);
        serverClosed = true;
    }

    logLine(tag, method, host, uri, status, bodyBytes);

    std::string respVer = firstToken(resp.startLine);
    closeAfter = serverClosed || wantsClose(req, version) || wantsClose(resp, respVer);
    return true;
}


// ============================================================
//  [MITM 본체] CONNECT → 양쪽 TLS + Plan A ALPN
// ============================================================
static bool isConnectPortAllowed(int port) {
    for (int p : ALLOWED_CONNECT_PORTS) if (p == port) return true;
    return false;
}

static void HandleConnectMITM(SOCKET clientSock, const std::string& target, std::string preRead) {
    std::string host, portStr;
    splitHostPort(target, host, portStr, "443");
    int port = atoi(portStr.c_str());

    if (!isConnectPortAllowed(port)) {
        sendRawSimple(clientSock, "403 Forbidden");
        logMsg("REJECT: CONNECT port not allowed: " + target);
        return;
    }

    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    SockStream rawOut(clientSock);
    if (!rawOut.writeAll(ok, strlen(ok))) return;

    SSL_CTX* sctx = g_ca.serverCtxForHost(host);
    if (!sctx) { logMsg("no server ctx: " + host); return; }

    // [세션1] 브라우저와 TLS (내가 서버役) — ALPN 은 서버ctx 콜백이 http/1.1 로 고정
    SSL* cssl = SSL_new(sctx);
    if (!cssl) return;
    BIO* cbio = BIO_new(g_prefixBioMethod);
    PrefixBioData* bd = new PrefixBioData{ clientSock, std::move(preRead), 0 };
    BIO_set_data(cbio, bd);
    BIO_set_init(cbio, 1);
    SSL_set_bio(cssl, cbio, cbio);
    if (SSL_accept(cssl) != 1) {
        // h2-only 클라(gRPC 등)는 http/1.1 미제안 → 여기서 실패(의도된 Plan A 한계)
        logMsg("client TLS handshake fail (ALPN h2-only?): " + host);
        SSL_free(cssl); delete bd; return;
    }

    // [세션2] 진짜 서버로 TCP + TLS (내가 클라役)
    SOCKET upstream = ConnectUpstream(host.c_str(), portStr.c_str());
    if (upstream == INVALID_SOCKET) {
        logMsg("upstream connect fail: " + target);
        SSL_free(cssl); delete bd; return;
    }
    setRecvTimeout(upstream, RECV_TIMEOUT_MS);

    SSL* ussl = SSL_new(g_clientCtx);
    SSL_set_fd(ussl, (int)upstream);
    SSL_set_tlsext_host_name(ussl, host.c_str());               // SNI
    SSL_set1_host(ussl, host.c_str());
    SSL_set_alpn_protos(ussl, ALPN_HTTP11, sizeof(ALPN_HTTP11)); // ★ Plan A: 세션2 ALPN → http/1.1 만 광고
    if (SSL_connect(ussl) != 1) {
        logMsg("upstream TLS handshake fail: " + host);
        SSL_free(ussl); closesocket(upstream);
        SSL_free(cssl); delete bd; return;
    }

    logMsg("MITM " + target + " established (decrypting, alpn=http/1.1)");

    // 복호화 평문 keep-alive 루프
    TlsStream cStream(cssl), uStream(ussl);
    SockReader cReader(&cStream), uReader(&uStream);
    while (true) {
        bool closeAfter = false;
        if (!proxyExchange("MITM", cReader, &cStream, uReader, &uStream, host, closeAfter)) break;
        if (closeAfter) break;
    }

    SSL_shutdown(cssl); SSL_shutdown(ussl);
    SSL_free(cssl); SSL_free(ussl);
    closesocket(upstream);
    delete bd;
    logMsg("MITM " + target + " closed");
}


// ============================================================
//  HandleClient: 평문 HTTP + CONNECT(MITM) 분기
//    평문 경로에도 Plan A 덤프/업로드 식별 적용
// ============================================================
static void HandleClient(SOCKET clientSock) {
    setRecvTimeout(clientSock, RECV_TIMEOUT_MS);
    SockStream clientRaw(clientSock);
    SockReader client(&clientRaw);

    SOCKET upstream = INVALID_SOCKET;
    std::unique_ptr<SockStream> upRaw;
    std::unique_ptr<SockReader> up;
    std::string curTarget;

    while (true) {
        HttpHead req;
        if (!readHead(client, req)) break;

        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) {
            sendRawSimple(clientSock, "400 Bad Request");
            break;
        }

        if (method == "CONNECT") {
            if (upstream != INVALID_SOCKET) { closesocket(upstream); upstream = INVALID_SOCKET; up.reset(); upRaw.reset(); }
            std::string pre = client.takeBuffered();
            HandleConnectMITM(clientSock, uri, std::move(pre));
            closesocket(clientSock);
            return;
        }

        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) { sendRawSimple(clientSock, "400 Bad Request"); break; }
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0; std::string err;
        BodyMode reqMode = requestBodyMode(req, reqLen, err);
        if (reqMode == BodyMode::Error) { sendRawSimple(clientSock, "400 Bad Request"); break; }

        dumpRequestView("HTTP", req, host, uri);               // ★ 평문 요청 덤프

        std::string boundary;
        bool upload = isUploadRequest(method, req, boundary);
        std::string bodyCap;
        std::string* capPtr = upload ? &bodyCap : nullptr;

        std::string target = host + ":" + port;
        if (upstream == INVALID_SOCKET || curTarget != target) {
            if (upstream != INVALID_SOCKET) closesocket(upstream);
            up.reset(); upRaw.reset();
            upstream = ConnectUpstream(host.c_str(), port.c_str());
            if (upstream == INVALID_SOCKET) { sendRawSimple(clientSock, "502 Bad Gateway"); break; }
            setRecvTimeout(upstream, RECV_TIMEOUT_MS);
            upRaw = std::make_unique<SockStream>(upstream);
            up = std::make_unique<SockReader>(upRaw.get());
            curTarget = target;
        }

        std::string headOut = serializeHead(req);
        if (!upRaw->writeAll(headOut.data(), headOut.size())) break;
        if (reqMode == BodyMode::Length)  { if (!client.forwardExact((size_t)reqLen, upRaw.get(), capPtr)) break; }
        else if (reqMode == BodyMode::Chunked) { if (!client.forwardChunked(upRaw.get(), capPtr)) break; }

        if (upload) logUpload("HTTP", host, uri, boundary, bodyCap,
                              reqMode == BodyMode::Length ? reqLen : -1);

        HttpHead resp;
        if (!readHead(*up, resp)) { sendRawSimple(clientSock, "502 Bad Gateway"); break; }
        int status = parseStatus(resp.startLine);

        dumpResponseView("HTTP", resp, status);                // ★ 평문 응답 덤프

        std::string respHeadOut = serializeHead(resp);
        if (!clientRaw.writeAll(respHeadOut.data(), respHeadOut.size())) break;

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        long long bodyBytes = 0; bool serverClosed = false;
        if (respMode == BodyMode::Length) {
            if (!up->forwardExact((size_t)respLen, &clientRaw)) break;
            bodyBytes = respLen;
        } else if (respMode == BodyMode::Chunked) {
            if (!up->forwardChunked(&clientRaw)) break;
        } else if (respMode == BodyMode::UntilClose) {
            up->forwardUntilClose(&clientRaw);
            serverClosed = true;
        }

        logLine("HTTP", method, host, uri, status, bodyBytes);

        std::string respVer = firstToken(resp.startLine);
        if (serverClosed || wantsClose(req, version) || wantsClose(resp, respVer)) break;
    }

    if (upstream != INVALID_SOCKET) closesocket(upstream);
    closesocket(clientSock);
}


// ============================================================
//  OpenSSL 전역 초기화
// ============================================================
static bool InitTLS() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (!g_ca.load(ROOT_CA_CERT, ROOT_CA_KEY)) {
        printf("[proxy_plan_A] Root CA 로드 실패 — docs/m4-mitm-setup.md 보고 rootCA.crt/key 준비\n");
        return false;
    }

    g_clientCtx = SSL_CTX_new(TLS_client_method());
    if (!g_clientCtx) return false;
    SSL_CTX_set_min_proto_version(g_clientCtx, TLS1_2_VERSION);
    // [PoC] upstream 인증서 검증 생략 — 제품에선 반드시 켜야 함(scope 문서 §5).
    SSL_CTX_set_verify(g_clientCtx, SSL_VERIFY_NONE, nullptr);

    g_prefixBioMethod = makePrefixBioMethod();
    return g_prefixBioMethod != nullptr;
}


// ============================================================
//  RunServer
// ============================================================
static void RunServer() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }
    if (!InitTLS()) { WSACleanup(); return; }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) { WSACleanup(); return; }

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

    printf("[proxy_plan_A] %d listening... (MITM + ALPN->http/1.1 + upload detect)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;
        std::thread(HandleClient, clientSock).detach();
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    RunServer();
    return 0;
}


/*
============================================================
 proxy_plan_A 의 알려진 한계 (docs/scope-and-protocol-coverage.md 와 함께 읽기)
============================================================
 - ALPN 다운그레이드는 h2-only 클라(gRPC 등)에겐 안 통함 → 세션1 handshake 실패. (Plan B(nghttp2) 에서 해소)
 - 업로드 식별은 캡처 상한(UPLOAD_CAPTURE_CAP)까지만 스캔 → 상한 넘는 body 의 뒤쪽 part 는 놓칠 수 있음.
 - Content-Encoding(gzip/br) 로 압축된 body 는 아직 해제 안 함 → 압축된 요청/응답 본문은 평문 스캔 불가(다음 작업).
 - upstream 인증서 검증 SSL_VERIFY_NONE (PoC). 제품은 PEER 검증 필수.
 - HTTP/3(QUIC)은 별개(scope 문서 §4, Plan C).
 - (proxy_v4 승계) absolute-form URI, hop-by-hop 헤더 정규화, Expect:100-continue, IPv6 host:port 미처리.
============================================================
*/
