/*
============================================================
 proxy_plan_B  —  proxy_plan_A + 실제 HTTP/2 파싱(nghttp2)
============================================================
 근거 문서: docs/scope-and-protocol-coverage.md (§2 Plan B), proxy_beyond_docs/README.md

 [Plan A 와의 차이 — 한 줄]
   Plan A: ALPN 로 h2 를 http/1.1 로 눌러 앉혀서 기존 1.1 파서로 처리.
   Plan B: ALPN 에서 h2 를 그대로 협상 → nghttp2 로 실제 h2 를 파싱한다.
           (h2 를 못/안 쓰는 클라는 http/1.1 경로로 자동 fallback — 두 경로 다 지원)

 [구조]
   CONNECT → 세션1 SSL_accept(브라우저, 내가 서버役) → 협상된 ALPN 확인
     - "http/1.1" → Plan A 와 동일한 HTTP/1.1 keep-alive 루프 (fallback)
     - "h2"       → 세션2 도 h2 로 붙이고 → H2 브릿지 실행

   [H2 브릿지 = h2-to-h2 리버스 프록시]
     - csess : nghttp2 server 세션 (브라우저 ↔ 프록시)
     - usess : nghttp2 client 세션 (프록시 ↔ 진짜 서버)
     - 브라우저가 연 stream(요청) 을 upstream stream 으로 매핑, 응답을 역방향 매핑.
     - HPACK 해제/프레이밍/흐름제어는 nghttp2 가, 우리는 콜백으로 헤더/DATA 를 받아 잇고
       그 평문 위에서 파일 업로드를 식별한다.
     - I/O: 두 소켓을 non-blocking + select 로 멀티플렉싱.

 [빌드]
   - OpenSSL + nghttp2 필요. vcpkg:  vcpkg install nghttp2:x64-windows
   - DLL: nghttp2.dll 을 exe 옆에 (또는 PATH). libssl/libcrypto DLL 도 동일.
   - rootCA.crt/key + OS 신뢰 등록: docs/m4-mitm-setup.md

 [상태] ★ 아직 빌드/실행 검증 안 함 — 컴파일·런타임 디버깅 필요. (설계·배선 우선 작성본)
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

// MSVC 에는 POSIX 의 ssize_t 가 없다. nghttp2.h 는 소비자 빌드에서 ssize_t 기반
// 콜백 typedef(nghttp2_data_source_read_callback 등)를 그대로 컴파일하므로,
// nghttp2 를 include 하기 전에 Windows SSIZE_T 로 정의해준다. (안 하면 헤더에서 C2065)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

#include <nghttp2/nghttp2.h>

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
#pragma comment(lib, "nghttp2.lib")

// ---------------- 설정 상수 ----------------
static const int    LISTEN_PORT      = 18080;
static const size_t MAX_HEAD_BYTES   = 64 * 1024;
static const long long MAX_BODY_LEN  = 1LL << 40;
static const int    RECV_TIMEOUT_MS  = 30000;
static const int    IO_CHUNK         = 16384;

static const bool   SHOW_FULL_HEADERS = true;
static const size_t UPLOAD_CAPTURE_CAP = 256 * 1024;

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
static void setNonBlocking(SOCKET s) {
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
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
static void logMsg(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    printf("[%s] %s\n", nowStamp().c_str(), msg.c_str());
}
static void logBlock(const std::string& block) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    fputs(block.c_str(), stdout);
}


// ============================================================
//  업로드 식별 헬퍼 (Plan A 와 공유)
// ============================================================
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
static void logUpload(const char* tag, const std::string& host, const std::string& path,
                      const std::string& boundary, const std::string& bodyCap) {
    std::vector<UploadPart> parts = scanMultipart(bodyCap);
    bool truncated = (bodyCap.size() >= UPLOAD_CAPTURE_CAP);

    std::string b;
    b += "  *** FILE UPLOAD DETECTED [" + std::string(tag) + "]  " + host + path + "\n";
    b += "      multipart/form-data; boundary=" + boundary + "\n";
    if (parts.empty()) {
        b += "      (no filename part in captured " + std::to_string(bodyCap.size()) +
             " bytes" + (truncated ? ", TRUNCATED" : "") + ")\n";
    } else {
        for (const auto& p : parts) {
            b += "      - field=\"" + p.field + "\" filename=\"" + p.filename + "\"";
            if (!p.partType.empty()) b += " type=\"" + p.partType + "\"";
            b += "\n";
        }
        if (truncated) b += "      (capture TRUNCATED at " + std::to_string(UPLOAD_CAPTURE_CAP) + " bytes)\n";
    }
    logBlock(b);
}


// ============================================================
//  Stream 추상화 + HTTP/1.1 파서 (Plan A 그대로 — h2 아닌 경로 fallback)
// ============================================================
class Stream {
public:
    virtual ~Stream() {}
    virtual int  read(char* buf, int len) = 0;
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
                off = nl + 1; compact(); return true;
            }
            if (buffer.size() - off > MAX_HEAD_BYTES) return false;
            if (!fill()) return false;
        }
    }
    bool readExact(size_t n, std::string& out) {
        while (buffer.size() - off < n) if (!fill()) return false;
        out.assign(buffer, off, n); off += n; compact(); return true;
    }
    bool forwardExact(size_t n, Stream* dest, std::string* cap = nullptr) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!dest->writeAll(buffer.data() + off, avail)) return false;
                if (cap && cap->size() < UPLOAD_CAPTURE_CAP)
                    cap->append(buffer.data() + off, (std::min)(avail, UPLOAD_CAPTURE_CAP - cap->size()));
                off += avail; n -= avail; compact();
            } else if (!fill()) return false;
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
        std::string s = buffer.substr(off); buffer.clear(); off = 0; return s;
    }
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
            if (!forwardExact((size_t)sz, dest, cap)) return false;
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
    Stream* src; std::string buffer; size_t off = 0;
};

struct HttpHead {
    std::string startLine;
    std::vector<std::pair<std::string, std::string>> headers;
};
static std::string headerGet(const HttpHead& h, const std::string& lname) {
    for (const auto& kv : h.headers) if (toLower(kv.first) == lname) return kv.second;
    return "";
}
static std::string serializeHead(const HttpHead& h) {
    std::string s = h.startLine + "\r\n";
    for (const auto& kv : h.headers) s += kv.first + ": " + kv.second + "\r\n";
    s += "\r\n"; return s;
}
static bool readHead(SockReader& r, HttpHead& head) {
    do { if (!r.readLine(head.startLine)) return false; } while (head.startLine.empty());
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
    for (char c : t) { if (c < '0' || c > '9') return false; v = v * 10 + (c - '0'); if (v > MAX_BODY_LEN) return false; }
    out = v; return true;
}
static BodyMode requestBodyMode(const HttpHead& h, long long& clen, std::string& err) {
    bool hasCL = false, hasTE = false; long long cl = -1; std::string te;
    for (const auto& kv : h.headers) {
        std::string n = toLower(kv.first);
        if (n == "content-length") {
            long long v;
            if (!parseContentLength(kv.second, v)) { err = "bad Content-Length"; return BodyMode::Error; }
            if (hasCL && cl != v) { err = "conflicting Content-Length"; return BodyMode::Error; }
            hasCL = true; cl = v;
        } else if (n == "transfer-encoding") { hasTE = true; te = toLower(kv.second); }
    }
    if (hasCL && hasTE) { err = "CL+TE smuggling"; return BodyMode::Error; }
    if (hasTE) { if (te.find("chunked") != std::string::npos) return BodyMode::Chunked; err = "bad TE"; return BodyMode::Error; }
    if (hasCL) { clen = cl; return BodyMode::Length; }
    return BodyMode::None;
}
static BodyMode responseBodyMode(const HttpHead& h, const std::string& reqMethod, int status, long long& clen) {
    if (reqMethod == "HEAD") return BodyMode::None;
    if ((status >= 100 && status < 200) || status == 204 || status == 304) return BodyMode::None;
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (!te.empty() && te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty()) { long long v; if (parseContentLength(cl, v)) { clen = v; return BodyMode::Length; } }
    return BodyMode::UntilClose;
}
static bool parseRequestLine(const std::string& line, std::string& m, std::string& u, std::string& v) {
    size_t s1 = line.find(' '); if (s1 == std::string::npos) return false;
    size_t s2 = line.find(' ', s1 + 1); if (s2 == std::string::npos) return false;
    m = line.substr(0, s1); u = line.substr(s1 + 1, s2 - s1 - 1); v = line.substr(s2 + 1);
    return !(m.empty() || u.empty() || v.empty());
}
static int parseStatus(const std::string& line) {
    size_t s1 = line.find(' '); if (s1 == std::string::npos) return 0;
    return atoi(line.c_str() + s1 + 1);
}
static std::string firstToken(const std::string& line) {
    size_t s = line.find(' '); return (s == std::string::npos) ? line : line.substr(0, s);
}
static void splitHostPort(const std::string& hp, std::string& host, std::string& port, const char* defPort) {
    size_t c = hp.find(':');
    if (c != std::string::npos && hp.find(':', c + 1) == std::string::npos) {
        host = hp.substr(0, c); port = hp.substr(c + 1); if (port.empty()) port = defPort;
    } else { host = hp; port = defPort; }
}
static bool wantsClose(const HttpHead& h, const std::string& version) {
    std::string conn = toLower(headerGet(h, "connection"));
    if (conn.find("close") != std::string::npos) return true;
    if (conn.find("keep-alive") != std::string::npos) return false;
    return (version == "HTTP/1.0");
}
static bool isUploadRequest(const std::string& method, const std::string& contentType, std::string& boundaryOut) {
    if (method != "POST" && method != "PUT" && method != "PATCH") return false;
    if (toLower(contentType).find("multipart/form-data") == std::string::npos) return false;
    boundaryOut = extractBoundary(contentType);
    return true;
}
static void dumpHeadView(const char* tag, const std::string& dir, const std::string& first,
                         const std::vector<std::pair<std::string,std::string>>& headers) {
    if (!SHOW_FULL_HEADERS) return;
    std::string b;
    b += "\n===== [" + std::string(tag) + "] " + dir + "  " + first + " =====\n";
    for (const auto& kv : headers) b += "  " + kv.first + ": " + kv.second + "\n";
    logBlock(b);
}


// ============================================================
//  upstream TCP 연결
// ============================================================
static SOCKET ConnectUpstream(const char* host, const char* port) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* info = nullptr;
    if (getaddrinfo(host, port, &hints, &info) != 0) return INVALID_SOCKET;
    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(info); return INVALID_SOCKET; }
    if (connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock); freeaddrinfo(info); return INVALID_SOCKET;
    }
    freeaddrinfo(info); return sock;
}


// ============================================================
//  ALPN
// ============================================================
static const unsigned char ALPN_H2[]     = { 2, 'h','2' };
static const unsigned char ALPN_HTTP11[] = { 8, 'h','t','t','p','/','1','.','1' };
static const unsigned char ALPN_BOTH[]   = { 2, 'h','2', 8, 'h','t','t','p','/','1','.','1' };

// 세션1(서버役): 클라 제안 중 h2 우선, 없으면 http/1.1. (둘 다 지원)
static int alpnSelectPreferH2(SSL*, const unsigned char** out, unsigned char* outlen,
                              const unsigned char* in, unsigned int inlen, void*) {
    if (SSL_select_next_proto((unsigned char**)out, outlen,
                              ALPN_BOTH, sizeof(ALPN_BOTH), in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
static bool alpnIsH2(SSL* ssl) {
    const unsigned char* p = nullptr; unsigned len = 0;
    SSL_get0_alpn_selected(ssl, &p, &len);
    return (len == 2 && memcmp(p, "h2", 2) == 0);
}


// ============================================================
//  [MITM 인프라] Root CA / leaf 동적 발급 (Plan A 와 동일 + ALPN 콜백만 교체)
// ============================================================
class CertAuthority {
public:
    bool load(const char* caCertPath, const char* caKeyPath) {
        BIO* bc = BIO_new_file(caCertPath, "rb");
        if (!bc) { logMsg(std::string("CA cert open fail: ") + caCertPath); return false; }
        caCert_ = PEM_read_bio_X509(bc, nullptr, nullptr, nullptr); BIO_free(bc);
        BIO* bk = BIO_new_file(caKeyPath, "rb");
        if (!bk) { logMsg(std::string("CA key open fail: ") + caKeyPath); return false; }
        caKey_ = PEM_read_bio_PrivateKey(bk, nullptr, nullptr, nullptr); BIO_free(bk);
        if (!caCert_ || !caKey_) { logMsg("CA parse fail"); return false; }
        leafKey_ = EVP_RSA_gen(2048);
        return leafKey_ != nullptr;
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
        SSL_CTX_set_alpn_select_cb(ctx, alpnSelectPreferH2, nullptr);   // ★ Plan B: h2 우선
        if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, leafKey_) != 1 ||
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(caCert_)) != 1) {
            logMsg("server ctx setup fail: " + host);
            X509_free(leaf); SSL_CTX_free(ctx); return nullptr;
        }
        X509_free(leaf);
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = cache_.find(host);
        if (it != cache_.end()) { SSL_CTX_free(ctx); return it->second; }
        cache_[host] = ctx; return ctx;
    }
private:
    X509* makeLeaf(const std::string& host) {
        X509* x = X509_new(); if (!x) return nullptr;
        X509_set_version(x, 2);
        unsigned char serial[8]; RAND_bytes(serial, sizeof(serial));
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)); BN_free(bn);
        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x), 60L*60*24*825);
        X509_set_pubkey(x, leafKey_);
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)host.c_str(), -1, -1, 0);
        X509_set_issuer_name(x, X509_get_subject_name(caCert_));
        X509V3_CTX ctx; X509V3_set_ctx(&ctx, caCert_, x, nullptr, nullptr, 0);
        std::string san = "DNS:" + host;
        addExt(x, &ctx, NID_subject_alt_name, san.c_str());
        addExt(x, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        addExt(x, &ctx, NID_ext_key_usage, "serverAuth");
        addExt(x, &ctx, NID_subject_key_identifier, "hash");
        addExt(x, &ctx, NID_authority_key_identifier, "keyid,issuer");
        if (X509_sign(x, caKey_, EVP_sha256()) == 0) { X509_free(x); return nullptr; }
        return x;
    }
    static void addExt(X509* x, X509V3_CTX* ctx, int nid, const char* value) {
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
        if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    }
    X509* caCert_ = nullptr; EVP_PKEY* caKey_ = nullptr; EVP_PKEY* leafKey_ = nullptr;
    std::mutex mtx_; std::map<std::string, SSL_CTX*> cache_;
};
static CertAuthority g_ca;
static SSL_CTX*      g_clientCtx = nullptr;


// ============================================================
//  pre-read 선주입 커스텀 BIO (세션1 handshake 용)
// ============================================================
struct PrefixBioData { SOCKET sock; std::string prefix; size_t off; };
static int prefixBioRead(BIO* b, char* out, int len) {
    PrefixBioData* d = (PrefixBioData*)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (d->off < d->prefix.size()) {
        int n = (std::min)(len, (int)(d->prefix.size() - d->off));
        memcpy(out, d->prefix.data() + d->off, n); d->off += (size_t)n; return n;
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
static long prefixBioCtrl(BIO*, int cmd, long, void*) { return (cmd == BIO_CTRL_FLUSH) ? 1 : 0; }
static BIO_METHOD* makePrefixBioMethod() {
    BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "prefix-sock");
    BIO_meth_set_read(m, prefixBioRead);
    BIO_meth_set_write(m, prefixBioWrite);
    BIO_meth_set_ctrl(m, prefixBioCtrl);
    return m;
}
static BIO_METHOD* g_prefixBioMethod = nullptr;


// ============================================================
//  ★ HTTP/2 브릿지 (nghttp2) — 본체
// ============================================================
struct H2Bridge;

struct H2Stream {
    int32_t   cid = -1;          // 브라우저측 stream id
    int32_t   uid = -1;          // upstream측 stream id
    H2Bridge* br = nullptr;

    // 요청(브라우저 → upstream)
    std::string method, path, scheme, authority, ctype;
    std::vector<std::pair<std::string,std::string>> reqHdr;  // 전달할 일반 헤더
    std::string reqBody;         // upstream 으로 보낼 대기 body
    bool reqEof = false;
    bool reqSubmitted = false;

    // 응답(upstream → 브라우저)
    std::vector<std::pair<std::string,std::string>> respHdr;
    std::string respBody;
    bool respEof = false;
    int  status = 0;
    bool respSubmitted = false;

    // 업로드 식별
    bool isUpload = false;
    std::string boundary;
    std::string uploadCap;
    bool uploadLogged = false;
};

struct H2Bridge {
    SSL* cssl = nullptr; SOCKET csock = INVALID_SOCKET; nghttp2_session* csess = nullptr; // 브라우저(server)
    SSL* ussl = nullptr; SOCKET usock = INVALID_SOCKET; nghttp2_session* usess = nullptr; // upstream(client)
    std::string host;
    std::map<int32_t, H2Stream*> byClient;
    std::map<int32_t, H2Stream*> byUpstream;
    std::vector<H2Stream*> all;
    bool cClosed = false, uClosed = false;

    H2Stream* newStream() { H2Stream* s = new H2Stream(); s->br = this; all.push_back(s); return s; }
};

// nghttp2 nv 빌더
static nghttp2_nv mkNv(const std::string& name, const std::string& value) {
    nghttp2_nv nv;
    nv.name = (uint8_t*)name.data(); nv.namelen = name.size();
    nv.value = (uint8_t*)value.data(); nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NONE;   // nghttp2 가 submit 시 복사함
    return nv;
}
static bool skipReqHeader(const std::string& lname) {
    // h2 에서 금지되거나 우리가 pseudo 로 대체하는 것들
    return lname == "connection" || lname == "keep-alive" || lname == "proxy-connection" ||
           lname == "transfer-encoding" || lname == "upgrade" || lname == "host" || lname == "te";
}

// ---- upstream(client) 세션: 요청 body data provider ----
static ssize_t reqBodyRead(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                           uint32_t* data_flags, nghttp2_data_source* source, void*) {
    H2Stream* s = (H2Stream*)source->ptr;
    if (s->reqBody.empty()) {
        if (s->reqEof) { *data_flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t n = (std::min)(length, s->reqBody.size());
    memcpy(buf, s->reqBody.data(), n);
    s->reqBody.erase(0, n);
    if (s->reqBody.empty() && s->reqEof) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}
// ---- 브라우저(server) 세션: 응답 body data provider ----
static ssize_t respBodyRead(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                            uint32_t* data_flags, nghttp2_data_source* source, void*) {
    H2Stream* s = (H2Stream*)source->ptr;
    if (s->respBody.empty()) {
        if (s->respEof) { *data_flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t n = (std::min)(length, s->respBody.size());
    memcpy(buf, s->respBody.data(), n);
    s->respBody.erase(0, n);
    if (s->respBody.empty() && s->respEof) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

// 브라우저 요청 헤더 완성 → upstream 으로 요청 제출
static void submitUpstreamRequest(H2Bridge* br, H2Stream* s, bool hasBody) {
    std::vector<nghttp2_nv> nva;
    std::string scheme = s->scheme.empty() ? "https" : s->scheme;
    std::string authority = s->authority.empty() ? br->host : s->authority;
    nva.push_back(mkNv(":method", s->method));
    nva.push_back(mkNv(":scheme", scheme));
    nva.push_back(mkNv(":path", s->path));
    nva.push_back(mkNv(":authority", authority));
    for (auto& kv : s->reqHdr) nva.push_back(mkNv(kv.first, kv.second));

    nghttp2_data_provider prd; prd.source.ptr = s; prd.read_callback = reqBodyRead;
    int32_t uid = nghttp2_submit_request(br->usess, nullptr, nva.data(), nva.size(),
                                         hasBody ? &prd : nullptr, s);
    if (uid < 0) { logMsg("submit_request fail: " + std::string(nghttp2_strerror(uid))); return; }
    s->uid = uid; s->reqSubmitted = true;
    br->byUpstream[uid] = s;

    dumpHeadView("MITM/h2", ">> REQUEST", s->method + " " + br->host + s->path, s->reqHdr);
}
// upstream 응답 헤더 완성 → 브라우저로 응답 제출
static void submitClientResponse(H2Bridge* br, H2Stream* s, bool hasBody) {
    std::vector<nghttp2_nv> nva;
    std::string st = std::to_string(s->status ? s->status : 502);
    nva.push_back(mkNv(":status", st));
    for (auto& kv : s->respHdr) nva.push_back(mkNv(kv.first, kv.second));

    nghttp2_data_provider prd; prd.source.ptr = s; prd.read_callback = respBodyRead;
    int rv = nghttp2_submit_response(br->csess, s->cid, nva.data(), nva.size(), hasBody ? &prd : nullptr);
    if (rv != 0) { logMsg("submit_response fail: " + std::string(nghttp2_strerror(rv))); return; }
    s->respSubmitted = true;

    dumpHeadView("MITM/h2", "<< RESPONSE (" + st + ")", br->host + s->path, s->respHdr);
}

// ---- 공통 콜백 (session user_data = H2Bridge*, side 는 session 비교로 판별) ----
static int cb_on_begin_headers(nghttp2_session* session, const nghttp2_frame* frame, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    if (session == br->csess && frame->hd.type == NGHTTP2_HEADERS &&
        frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        H2Stream* s = br->newStream();
        s->cid = frame->hd.stream_id;
        br->byClient[s->cid] = s;
        nghttp2_session_set_stream_user_data(session, s->cid, s);
    }
    return 0;
}
static int cb_on_header(nghttp2_session* session, const nghttp2_frame* frame,
                        const uint8_t* name, size_t namelen,
                        const uint8_t* value, size_t valuelen, uint8_t, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    std::string n((const char*)name, namelen), v((const char*)value, valuelen);
    int32_t sid = frame->hd.stream_id;

    if (session == br->csess) {   // 브라우저 요청 헤더
        H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
        if (!s) return 0;
        if (n == ":method")         s->method = v;
        else if (n == ":path")      s->path = v;
        else if (n == ":scheme")    s->scheme = v;
        else if (n == ":authority") s->authority = v;
        else {
            if (n == "content-type") s->ctype = v;
            if (!skipReqHeader(n)) s->reqHdr.push_back({ n, v });
        }
    } else {                      // upstream 응답 헤더
        H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
        if (!s) return 0;
        if (n == ":status") s->status = atoi(v.c_str());
        else if (!n.empty() && n[0] != ':') s->respHdr.push_back({ n, v });
    }
    return 0;
}
static int cb_on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    int32_t sid = frame->hd.stream_id;
    bool endStream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;

    if (session == br->csess) {
        // 브라우저측
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
            if (!s) return 0;
            std::string b;
            s->isUpload = isUploadRequest(s->method, s->ctype, b);
            s->boundary = b;
            if (endStream) s->reqEof = true;
            submitUpstreamRequest(br, s, !endStream);   // body 없으면 provider 없이
        } else if (frame->hd.type == NGHTTP2_DATA && endStream) {
            H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
            if (s) {
                s->reqEof = true;
                if (s->uid >= 0) nghttp2_session_resume_data(br->usess, s->uid);
                if (s->isUpload && !s->uploadLogged) {
                    logUpload("MITM/h2", br->host, s->path, s->boundary, s->uploadCap);
                    s->uploadLogged = true;
                }
            }
        }
    } else {
        // upstream측
        if (frame->hd.type == NGHTTP2_HEADERS) {
            H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
            if (!s) return 0;
            if (endStream) s->respEof = true;
            submitClientResponse(br, s, !endStream);
        } else if (frame->hd.type == NGHTTP2_DATA && endStream) {
            H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
            if (s) { s->respEof = true; if (s->cid >= 0) nghttp2_session_resume_data(br->csess, s->cid); }
        }
    }
    return 0;
}
static int cb_on_data_chunk(nghttp2_session* session, uint8_t, int32_t sid,
                            const uint8_t* data, size_t len, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    if (session == br->csess) {   // 요청 body (브라우저 → upstream)
        H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
        if (!s) return 0;
        s->reqBody.append((const char*)data, len);
        if (s->isUpload && s->uploadCap.size() < UPLOAD_CAPTURE_CAP)
            s->uploadCap.append((const char*)data,
                                (std::min)(len, UPLOAD_CAPTURE_CAP - s->uploadCap.size()));
        if (s->uid >= 0) nghttp2_session_resume_data(br->usess, s->uid);
    } else {                      // 응답 body (upstream → 브라우저)
        H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
        if (!s) return 0;
        s->respBody.append((const char*)data, len);
        if (s->cid >= 0) nghttp2_session_resume_data(br->csess, s->cid);
    }
    return 0;
}
static int cb_on_stream_close(nghttp2_session* session, int32_t sid, uint32_t, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    if (session == br->csess) {
        H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
        if (s && s->uid >= 0 && !s->respEof)
            nghttp2_submit_rst_stream(br->usess, NGHTTP2_FLAG_NONE, s->uid, NGHTTP2_CANCEL);
    } else {
        H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
        if (s && s->cid >= 0 && !s->respEof)
            nghttp2_submit_rst_stream(br->csess, NGHTTP2_FLAG_NONE, s->cid, NGHTTP2_INTERNAL_ERROR);
    }
    return 0;
    // 실제 free 는 브릿지 종료 시 일괄(PoC). 장수명 연결의 스트림 누적은 한계로 기록.
}

// send 콜백: nghttp2 → SSL (non-blocking)
static ssize_t sslSendCb(SSL* ssl, const uint8_t* data, size_t length) {
    int n = SSL_write(ssl, data, (int)length);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) return NGHTTP2_ERR_WOULDBLOCK;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}
static ssize_t cb_send_client(nghttp2_session*, const uint8_t* data, size_t length, int, void* user) {
    return sslSendCb(((H2Bridge*)user)->cssl, data, length);
}
static ssize_t cb_send_upstream(nghttp2_session*, const uint8_t* data, size_t length, int, void* user) {
    return sslSendCb(((H2Bridge*)user)->ussl, data, length);
}

static nghttp2_session_callbacks* makeCallbacks(bool isServerSide) {
    nghttp2_session_callbacks* cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, isServerSide ? cb_send_client : cb_send_upstream);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, cb_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, cb_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, cb_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, cb_on_stream_close);
    return cbs;
}

// SSL 소켓에서 읽어 nghttp2 로 먹인다. 반환 false = 세션 종료.
static bool pumpRecv(SSL* ssl, nghttp2_session* sess, bool& closed) {
    char buf[IO_CHUNK];
    for (;;) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            ssize_t rv = nghttp2_session_mem_recv(sess, (const uint8_t*)buf, (size_t)n);
            if (rv < 0) { logMsg(std::string("mem_recv: ") + nghttp2_strerror((int)rv)); return false; }
            continue;
        }
        int e = SSL_get_error(ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return true;
        closed = true;   // close-notify or error
        return true;
    }
}

static void runH2Bridge(H2Bridge* br) {
    // 세션 생성
    nghttp2_session_callbacks* scbs = makeCallbacks(true);
    nghttp2_session_server_new(&br->csess, scbs, br);
    nghttp2_session_callbacks_del(scbs);

    nghttp2_session_callbacks* ccbs = makeCallbacks(false);
    nghttp2_session_client_new(&br->usess, ccbs, br);
    nghttp2_session_callbacks_del(ccbs);

    // 초기 SETTINGS 제출
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
    nghttp2_submit_settings(br->csess, NGHTTP2_FLAG_NONE, iv, 1);
    nghttp2_submit_settings(br->usess, NGHTTP2_FLAG_NONE, iv, 1);

    setNonBlocking(br->csock);
    setNonBlocking(br->usock);

    logMsg("MITM/h2 " + br->host + " bridge established (decrypting h2)");

    for (;;) {
        // 우선 대기중인 송신 flush
        if (nghttp2_session_send(br->csess) != 0) break;
        if (nghttp2_session_send(br->usess) != 0) break;

        bool cWR = nghttp2_session_want_read(br->csess) != 0;
        bool cWW = nghttp2_session_want_write(br->csess) != 0;
        bool uWR = nghttp2_session_want_read(br->usess) != 0;
        bool uWW = nghttp2_session_want_write(br->usess) != 0;

        if (br->cClosed && br->uClosed) break;
        if (!cWR && !cWW && !uWR && !uWW) break;

        fd_set rfds, wfds; FD_ZERO(&rfds); FD_ZERO(&wfds);
        if (!br->cClosed) FD_SET(br->csock, &rfds);
        if (!br->uClosed) FD_SET(br->usock, &rfds);
        if (cWW) FD_SET(br->csock, &wfds);
        if (uWW) FD_SET(br->usock, &wfds);

        timeval tv; tv.tv_sec = 30; tv.tv_usec = 0;
        int r = select(0, &rfds, &wfds, nullptr, &tv);
        if (r == 0) { logMsg("MITM/h2 idle timeout: " + br->host); break; }
        if (r == SOCKET_ERROR) break;

        if (FD_ISSET(br->csock, &rfds)) {
            if (!pumpRecv(br->cssl, br->csess, br->cClosed)) break;
        }
        if (FD_ISSET(br->usock, &rfds)) {
            if (!pumpRecv(br->ussl, br->usess, br->uClosed)) break;
        }
        // 송신은 루프 상단에서 flush
    }

    // 정리
    for (H2Stream* s : br->all) delete s;
    if (br->csess) nghttp2_session_del(br->csess);
    if (br->usess) nghttp2_session_del(br->usess);
    logMsg("MITM/h2 " + br->host + " bridge closed");
}


// ============================================================
//  HTTP/1.1 경로 (fallback) — Plan A 와 동일한 1 exchange
// ============================================================
static bool proxyExchange11(const char* tag, SockReader& cr, Stream* cOut,
                            SockReader& ur, Stream* uOut, const std::string& host, bool& closeAfter) {
    closeAfter = true;
    HttpHead req;
    if (!readHead(cr, req)) return false;
    std::string method, uri, version;
    if (!parseRequestLine(req.startLine, method, uri, version)) return false;
    long long reqLen = 0; std::string err;
    BodyMode reqMode = requestBodyMode(req, reqLen, err);
    if (reqMode == BodyMode::Error) { logMsg(std::string("REJECT: ") + err); return false; }

    dumpHeadView(tag, ">> REQUEST", req.startLine, req.headers);

    std::string boundary;
    bool upload = isUploadRequest(method, headerGet(req, "content-type"), boundary);
    std::string bodyCap; std::string* capPtr = upload ? &bodyCap : nullptr;

    std::string headOut = serializeHead(req);
    if (!uOut->writeAll(headOut.data(), headOut.size())) return false;
    if (reqMode == BodyMode::Length)  { if (!cr.forwardExact((size_t)reqLen, uOut, capPtr)) return false; }
    else if (reqMode == BodyMode::Chunked) { if (!cr.forwardChunked(uOut, capPtr)) return false; }

    if (upload) logUpload(tag, host, uri, boundary, bodyCap);

    HttpHead resp;
    if (!readHead(ur, resp)) return false;
    int status = parseStatus(resp.startLine);
    dumpHeadView(tag, "<< RESPONSE", resp.startLine, resp.headers);

    std::string respHeadOut = serializeHead(resp);
    if (!cOut->writeAll(respHeadOut.data(), respHeadOut.size())) return false;
    long long respLen = 0;
    BodyMode respMode = responseBodyMode(resp, method, status, respLen);
    bool serverClosed = false;
    if (respMode == BodyMode::Length) { if (!ur.forwardExact((size_t)respLen, cOut)) return false; }
    else if (respMode == BodyMode::Chunked) { if (!ur.forwardChunked(cOut)) return false; }
    else if (respMode == BodyMode::UntilClose) { ur.forwardUntilClose(cOut); serverClosed = true; }

    logMsg(std::string(tag) + " " + method + " " + host + uri + " -> " + std::to_string(status));
    std::string respVer = firstToken(resp.startLine);
    closeAfter = serverClosed || wantsClose(req, version) || wantsClose(resp, respVer);
    return true;
}


// ============================================================
//  CONNECT → MITM (ALPN 협상 결과로 h2/1.1 분기)
// ============================================================
static bool isConnectPortAllowed(int port) {
    for (int p : ALLOWED_CONNECT_PORTS) if (p == port) return true;
    return false;
}

static void HandleConnectMITM(SOCKET clientSock, const std::string& target, std::string preRead) {
    std::string host, portStr;
    splitHostPort(target, host, portStr, "443");
    int port = atoi(portStr.c_str());
    if (!isConnectPortAllowed(port)) { logMsg("REJECT port: " + target); return; }

    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (send(clientSock, ok, (int)strlen(ok), 0) <= 0) { closesocket(clientSock); return; }

    SSL_CTX* sctx = g_ca.serverCtxForHost(host);
    if (!sctx) { closesocket(clientSock); return; }

    // [세션1] 브라우저와 TLS
    SSL* cssl = SSL_new(sctx);
    BIO* cbio = BIO_new(g_prefixBioMethod);
    PrefixBioData* bd = new PrefixBioData{ clientSock, std::move(preRead), 0 };
    BIO_set_data(cbio, bd); BIO_set_init(cbio, 1);
    SSL_set_bio(cssl, cbio, cbio);
    if (SSL_accept(cssl) != 1) {
        logMsg("client handshake fail: " + host);
        SSL_free(cssl); delete bd; closesocket(clientSock); return;
    }
    bool clientH2 = alpnIsH2(cssl);

    // [세션2] 진짜 서버 — 클라와 같은 프로토콜만 광고(번역 회피)
    SOCKET upstream = ConnectUpstream(host.c_str(), portStr.c_str());
    if (upstream == INVALID_SOCKET) { SSL_free(cssl); delete bd; closesocket(clientSock); return; }
    setRecvTimeout(upstream, RECV_TIMEOUT_MS);
    SSL* ussl = SSL_new(g_clientCtx);
    SSL_set_fd(ussl, (int)upstream);
    SSL_set_tlsext_host_name(ussl, host.c_str());
    SSL_set1_host(ussl, host.c_str());
    if (clientH2) SSL_set_alpn_protos(ussl, ALPN_H2, sizeof(ALPN_H2));
    else          SSL_set_alpn_protos(ussl, ALPN_HTTP11, sizeof(ALPN_HTTP11));
    if (SSL_connect(ussl) != 1) {
        logMsg("upstream handshake fail: " + host);
        SSL_free(ussl); closesocket(upstream); SSL_free(cssl); delete bd; closesocket(clientSock); return;
    }
    bool upstreamH2 = alpnIsH2(ussl);

    if (clientH2 != upstreamH2) {
        // 프로토콜 불일치(h2↔1.1 번역 미구현) — PoC 한계로 종료.
        logMsg("ALPN mismatch (client h2=" + std::to_string(clientH2) +
               ", upstream h2=" + std::to_string(upstreamH2) + "): " + host + " — translation not implemented");
        SSL_free(ussl); closesocket(upstream); SSL_free(cssl); delete bd; closesocket(clientSock); return;
    }

    if (clientH2) {
        // ---- HTTP/2 브릿지 ----
        H2Bridge br;
        br.cssl = cssl; br.csock = clientSock;
        br.ussl = ussl; br.usock = upstream;
        br.host = host;
        runH2Bridge(&br);
    } else {
        // ---- HTTP/1.1 keep-alive 루프 (fallback) ----
        logMsg("MITM/1.1 " + target + " established (decrypting http/1.1)");
        TlsStream cStream(cssl), uStream(ussl);
        SockReader cReader(&cStream), uReader(&uStream);
        while (true) {
            bool closeAfter = false;
            if (!proxyExchange11("MITM/1.1", cReader, &cStream, uReader, &uStream, host, closeAfter)) break;
            if (closeAfter) break;
        }
    }

    SSL_shutdown(cssl); SSL_shutdown(ussl);
    SSL_free(cssl); SSL_free(ussl);
    closesocket(upstream); delete bd; closesocket(clientSock);
}


// ============================================================
//  HandleClient: 평문 HTTP + CONNECT
// ============================================================
static void HandleClient(SOCKET clientSock) {
    setRecvTimeout(clientSock, RECV_TIMEOUT_MS);
    SockStream clientRaw(clientSock);
    SockReader client(&clientRaw);

    while (true) {
        HttpHead req;
        if (!readHead(client, req)) break;
        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) break;

        if (method == "CONNECT") {
            std::string pre = client.takeBuffered();
            HandleConnectMITM(clientSock, uri, std::move(pre));
            return;   // MITM 이 소켓을 닫음
        }

        // 평문 HTTP (한 요청 후 단순 처리)
        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) break;
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0; std::string err;
        BodyMode reqMode = requestBodyMode(req, reqLen, err);
        if (reqMode == BodyMode::Error) break;

        dumpHeadView("HTTP", ">> REQUEST", req.startLine, req.headers);

        std::string boundary;
        bool upload = isUploadRequest(method, headerGet(req, "content-type"), boundary);
        std::string bodyCap; std::string* capPtr = upload ? &bodyCap : nullptr;

        SOCKET upstream = ConnectUpstream(host.c_str(), port.c_str());
        if (upstream == INVALID_SOCKET) break;
        SockStream upStreamS(upstream);
        SockReader up(&upStreamS);

        std::string headOut = serializeHead(req);
        if (!upStreamS.writeAll(headOut.data(), headOut.size())) { closesocket(upstream); break; }
        if (reqMode == BodyMode::Length)  client.forwardExact((size_t)reqLen, &upStreamS, capPtr);
        else if (reqMode == BodyMode::Chunked) client.forwardChunked(&upStreamS, capPtr);

        if (upload) logUpload("HTTP", host, uri, boundary, bodyCap);

        HttpHead resp;
        if (!readHead(up, resp)) { closesocket(upstream); break; }
        int status = parseStatus(resp.startLine);
        dumpHeadView("HTTP", "<< RESPONSE", resp.startLine, resp.headers);

        std::string respHeadOut = serializeHead(resp);
        if (!clientRaw.writeAll(respHeadOut.data(), respHeadOut.size())) { closesocket(upstream); break; }
        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        bool serverClosed = false;
        if (respMode == BodyMode::Length) up.forwardExact((size_t)respLen, &clientRaw);
        else if (respMode == BodyMode::Chunked) up.forwardChunked(&clientRaw);
        else if (respMode == BodyMode::UntilClose) { up.forwardUntilClose(&clientRaw); serverClosed = true; }

        logMsg("HTTP " + method + " " + host + uri + " -> " + std::to_string(status));
        closesocket(upstream);
        if (serverClosed || wantsClose(req, version) || wantsClose(resp, firstToken(resp.startLine))) break;
    }
    closesocket(clientSock);
}


// ============================================================
//  초기화 + RunServer
// ============================================================
static bool InitTLS() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if (!g_ca.load(ROOT_CA_CERT, ROOT_CA_KEY)) {
        printf("[proxy_plan_B] Root CA 로드 실패 — docs/m4-mitm-setup.md\n");
        return false;
    }
    g_clientCtx = SSL_CTX_new(TLS_client_method());
    if (!g_clientCtx) return false;
    SSL_CTX_set_min_proto_version(g_clientCtx, TLS1_2_VERSION);
    SSL_CTX_set_verify(g_clientCtx, SSL_VERIFY_NONE, nullptr);   // [PoC]
    g_prefixBioMethod = makePrefixBioMethod();
    return g_prefixBioMethod != nullptr;
}
static void RunServer() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
    if (!InitTLS()) { WSACleanup(); return; }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) { WSACleanup(); return; }
    BOOL yes = TRUE;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(LISTEN_PORT); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(listenSock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError()); closesocket(listenSock); WSACleanup(); return;
    }
    listen(listenSock, SOMAXCONN);
    printf("[proxy_plan_B] %d listening... (MITM + real HTTP/2 via nghttp2, http/1.1 fallback)\n", LISTEN_PORT);

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
 proxy_plan_B 의 알려진 한계 / 미검증 지점
============================================================
 - ★ 빌드/실행 미검증. 특히 nghttp2 콜백 흐름·non-blocking select 루프·data provider
   resume 타이밍은 실제 트래픽으로 디버깅 필요.
 - 프로토콜 번역 미구현: 클라 h2 ↔ upstream 1.1 (또는 반대) 불일치면 종료.
   (major 사이트는 대부분 h2 지원이라 실제로는 드묾)
 - H2Stream free 는 브릿지 종료 시 일괄 → 장수명 연결에서 스트림 누적(메모리). 제품이면 stream_close 에서 회수.
 - Content-Encoding(gzip/br) 미해제 — 압축 body 는 평문 스캔 불가(업로드 식별은 헤더/multipart 위주라 대개 무압축).
 - upstream 인증서 검증 SSL_VERIFY_NONE (PoC).
 - HTTP/3(QUIC)은 별개(scope 문서 §4, Plan C).
 - 흐름제어/윈도우는 nghttp2 기본에 의존. 대용량 스트리밍 튜닝은 별도.
============================================================
*/
