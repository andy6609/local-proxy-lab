/*
============================================================
 proxy_v4  —  M4/M5: TLS MITM (HTTPS 복호화)  [+ M1~M3 전부 포함]
============================================================
 execution-plan-to-mitm.md 의 M4(MITM 기초) + M5(평문 분석) 을 제품 수준으로.
 proxy_v3(M3: CONNECT raw 터널)에서 'blind 통과'였던 자리를 TLS 가로채기로 채웠다.

 [한 줄 요약]
   v3: CONNECT -> 200 -> 암호 바이트 그대로 통과 (내용 못 봄)
   v4: CONNECT -> 200 -> *내가 직접 TLS 를 양쪽으로 끊음* -> 평문 HTTP 분석 -> 재암호화 전달

 [어떻게 'TLS 를 끊나' (MITM 의 핵심 구조)]
   브라우저  <== TLS 세션1 ==>  [프록시]  <== TLS 세션2 ==>  진짜 서버
                (내가 서버役)            (내가 클라役)
   - 세션1: 프록시가 '진짜 서버인 척' 한다. 그러려면 그 도메인용 인증서가 필요.
            -> Root CA 로 host 별 leaf 인증서를 즉석에서 만들어 서명(M5 의 동적 인증서).
            -> 브라우저가 그 인증서를 믿게 하려면 Root CA 를 OS 신뢰 저장소에 등록해둬야 함(설정).
   - 세션2: 프록시가 진짜 서버에 '평범한 TLS 클라이언트'로 접속.
   - 두 세션 사이에서 복호화된 평문이 흐른다 -> M2 파서로 그대로 분석.

 [v3 -> v4 의 가장 중요한 설계 변화: Stream 추상화]
   v3 의 SockReader 는 SOCKET 에 recv/send 를 직접 했다.
   v4 는 같은 파싱 로직이 '평문 소켓'과 '복호화된 TLS' 둘 다에서 돌아야 한다.
   -> 입출력을 Stream 인터페이스로 추상화:
        - SockStream : recv/send       (평문 HTTP 경로)
        - TlsStream  : SSL_read/SSL_write (MITM 복호화 경로)
   => M2 의 HTTP 파서(readHead/body framing)는 한 줄도 안 고치고 양쪽에서 재사용.
      이게 "암호화 통신이 프록시 안에서 평문으로 분석된다"의 실제 구현.

 [중요한 함정 두 가지]
   1) pre-read 바이트(v3 와 정반대 처리!):
      v3 에선 CONNECT 뒤에 미리 읽힌 바이트(=ClientHello)를 'upstream 으로' 흘려보냈다.
      v4 에선 그 ClientHello 는 *프록시 자신의 TLS 서버 입력*이다 -> upstream 이 아니라
      내 SSL_accept 가 먹어야 한다. -> 커스텀 BIO 로 버퍼 선주입(injectPrefix).
   2) upstream 인증서 검증:
      PoC 라 기본은 검증 생략(아무 https 나 붙게). 제품은 반드시 CA 번들로 검증해야 함
      (안 그러면 프록시가 진짜 서버에 대한 MITM 에 취약). -> 아래 한계 블록 참고.

 [빌드/설정] 반드시 docs/m4-mitm-setup.md 를 먼저 보고:
   - OpenSSL 개발 라이브러리 설치 + VS include/lib 경로 설정
   - Root CA 생성(openssl CLI) + Windows 신뢰 저장소 등록
   - rootCA.crt / rootCA.key 경로를 아래 ROOT_CA_CERT / ROOT_CA_KEY 에 맞추기
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
#include <atomic>
#include <map>
#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
// OpenSSL: vcpkg / slproweb 모두 보통 아래 이름. 다르면 docs 보고 바꿔라.
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

// ---------------- 설정 상수 ----------------
static const int    LISTEN_PORT      = 18080;
static const size_t MAX_HEAD_BYTES   = 64 * 1024;
static const long long MAX_BODY_LEN  = 1LL << 40;
static const int    RECV_TIMEOUT_MS  = 30000;
static const int    IO_CHUNK         = 16384;

static const int ALLOWED_CONNECT_PORTS[] = { 443 };

// Root CA 파일 경로 (docs/m4-mitm-setup.md 에서 openssl 로 생성).
//  - 절대경로 권장. 실행 작업폴더가 헷갈리면 여기서 고정.
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
//  Stream: 입출력 추상화 (★ v4 의 핵심 설계)
//   - SockStream : 평문 소켓 (recv/send)
//   - TlsStream  : 복호화된 TLS (SSL_read/SSL_write)
//   파서/릴레이는 Stream 만 알면 되고, 평문이든 TLS 든 똑같이 동작.
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
    int read(char* buf, int len) override {
        return recv(sock, buf, len, 0);
    }
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
    int read(char* buf, int len) override {
        int n = SSL_read(ssl, buf, len);
        return n;   // <=0 : close-notify / 에러
    }
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
//  SockReader: Stream 위의 버퍼드 리더 (M2 와 동일, 입출력만 Stream)
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

    bool forwardExact(size_t n, Stream* dest) {
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!dest->writeAll(buffer.data() + off, avail)) return false;
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

    // CONNECT 헤드를 읽다 미리 읽힌(over-read) 잉여 바이트를 꺼내 비움.
    //   MITM 에서는 이게 '클라의 ClientHello 시작분' -> 내 SSL_accept 에 선주입해야 함.
    std::string takeBuffered() {
        std::string s = buffer.substr(off);
        buffer.clear(); off = 0;
        return s;
    }

    bool forwardChunked(Stream* dest) {
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
            if (!forwardExact((size_t)sz, dest)) return false;
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
//  HTTP 헤드 + 파서들 (M2 와 동일 — 한 줄도 안 바꿈)
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
//  [MITM 인프라 1] Root CA 로딩 + host 별 leaf 인증서 동적 생성/캐시
// ============================================================
class CertAuthority {
public:
    // Root CA(cert/key) PEM 로드 + leaf 들이 공유할 키 1개 생성.
    //   주의: fopen+FILE* 를 OpenSSL DLL 에 넘기면 'no OPENSSL_Applink' 로 죽는다(CRT 경계).
    //         그래서 BIO_new_file + PEM_read_bio_* 를 쓴다(DLL 안전).
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

        // 모든 leaf 가 공유할 키 1개(매번 새로 만들면 느림). RSA 2048.
        leafKey_ = EVP_RSA_gen(2048);
        if (!leafKey_) { logMsg("leaf key gen fail"); return false; }
        return true;
    }

    // host 용 TLS 서버 컨텍스트(SSL_CTX) 를 얻는다(캐시). leaf 인증서를 즉석 발급.
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
        if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, leafKey_) != 1 ||
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(caCert_)) != 1) {
            logMsg("server ctx cert setup fail for " + host);
            X509_free(leaf); SSL_CTX_free(ctx); return nullptr;
        }
        X509_free(leaf);  // SSL_CTX_use_certificate 가 내부적으로 up-ref 함

        std::lock_guard<std::mutex> lk(mtx_);
        auto it = cache_.find(host);
        if (it != cache_.end()) { SSL_CTX_free(ctx); return it->second; } // 경쟁 시 먼저 것 사용
        cache_[host] = ctx;
        return ctx;
    }

private:
    // host(CN + SAN) 용 leaf 인증서를 Root CA 로 서명해서 발급.
    X509* makeLeaf(const std::string& host) {
        X509* x = X509_new();
        if (!x) return nullptr;

        X509_set_version(x, 2);                       // v3

        // 랜덤 시리얼 (8바이트)
        unsigned char serial[8];
        RAND_bytes(serial, sizeof(serial));
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
        BN_free(bn);

        X509_gmtime_adj(X509_getm_notBefore(x), -3600);          // 1시간 전
        X509_gmtime_adj(X509_getm_notAfter(x),  60L*60*24*825);  // ~825일

        X509_set_pubkey(x, leafKey_);

        // subject: CN = host
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char*)host.c_str(), -1, -1, 0);
        // issuer = CA subject
        X509_set_issuer_name(x, X509_get_subject_name(caCert_));

        // v3 확장: SAN, basicConstraints, EKU, SKID/AKID (ctx 로 issuer 연결)
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
static SSL_CTX*      g_clientCtx = nullptr;  // upstream(진짜 서버)에 붙을 때 쓰는 클라 컨텍스트


// ============================================================
//  [MITM 인프라 2] pre-read 바이트를 SSL_accept 에 선주입하는 커스텀 BIO
//   - CONNECT 줄 뒤에 이미 읽힌 ClientHello 시작분(prefix)을 먼저 내보내고,
//     그 다음부터는 소켓에서 직접 recv. (보통 prefix 는 비어있지만 안전하게 처리)
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
//  [MITM 인프라 3] 평문 한 번의 요청/응답 교환 (M2 로직, Stream 기반)
//   client(reader/out) <-> upstream(reader/out) 사이 1 exchange.
//   반환 false 면 루프 종료. status/host/uri 는 로깅용.
// ============================================================
static bool proxyExchange(const char* tag,
                          SockReader& cr, Stream* cOut,
                          SockReader& ur, Stream* uOut,
                          const std::string& host,
                          bool& closeAfter) {
    closeAfter = true;

    // 1. 요청 헤드 읽기 (복호화된 평문!)
    HttpHead req;
    if (!readHead(cr, req)) return false;

    std::string method, uri, version;
    if (!parseRequestLine(req.startLine, method, uri, version)) return false;

    long long reqLen = 0; std::string err;
    BodyMode reqMode = requestBodyMode(req, reqLen, err);
    if (reqMode == BodyMode::Error) { logMsg(std::string("REJECT: ") + err); return false; }

    // 2. 요청을 upstream(진짜 서버, TLS)으로 전달
    std::string headOut = serializeHead(req);
    if (!uOut->writeAll(headOut.data(), headOut.size())) return false;
    if (reqMode == BodyMode::Length) { if (!cr.forwardExact((size_t)reqLen, uOut)) return false; }
    else if (reqMode == BodyMode::Chunked) { if (!cr.forwardChunked(uOut)) return false; }

    // 3. 응답 헤드 읽기
    HttpHead resp;
    if (!readHead(ur, resp)) return false;
    int status = parseStatus(resp.startLine);

    // 4. 응답을 client(브라우저, TLS)로 전달
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

    // 5. 로그 — 여기서 HTTPS 의 평문 method/host/uri/status 가 보인다 (W6 의 목표)
    logLine(tag, method, host, uri, status, bodyBytes);

    std::string respVer = firstToken(resp.startLine);
    closeAfter = serverClosed || wantsClose(req, version) || wantsClose(resp, respVer);
    return true;
}


// ============================================================
//  [MITM 본체] CONNECT 를 받아 양쪽 TLS 를 끊고 평문을 분석
//   ★ v3 의 'blind 통과' 자리를 이걸로 교체한 것.
// ============================================================
static bool isConnectPortAllowed(int port) {
    for (int p : ALLOWED_CONNECT_PORTS) if (p == port) return true;
    return false;
}

static void HandleConnectMITM(SOCKET clientSock, SockReader& /*rawClient*/,
                              const std::string& target, std::string preRead) {
    std::string host, portStr;
    splitHostPort(target, host, portStr, "443");
    int port = atoi(portStr.c_str());

    if (!isConnectPortAllowed(port)) {
        sendRawSimple(clientSock, "403 Forbidden");
        logMsg("REJECT: CONNECT port not allowed: " + target);
        return;
    }

    // 1. 브라우저에 "터널 OK" — 이걸 받아야 브라우저가 ClientHello 를 보냄
    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    SockStream rawOut(clientSock);
    if (!rawOut.writeAll(ok, strlen(ok))) return;

    // 2. host 용 서버 컨텍스트(leaf 인증서) 확보
    SSL_CTX* sctx = g_ca.serverCtxForHost(host);
    if (!sctx) { logMsg("no server ctx: " + host); return; }

    // 3. [세션1] 브라우저와 TLS handshake — *내가 서버役* (가짜=내가 서명한 인증서)
    //    pre-read 로 미리 들어온 ClientHello 시작분을 커스텀 BIO 로 선주입.
    SSL* cssl = SSL_new(sctx);
    if (!cssl) return;
    BIO* cbio = BIO_new(g_prefixBioMethod);
    PrefixBioData* bd = new PrefixBioData{ clientSock, std::move(preRead), 0 };
    BIO_set_data(cbio, bd);
    BIO_set_init(cbio, 1);
    SSL_set_bio(cssl, cbio, cbio);              // read/write 같은 BIO
    if (SSL_accept(cssl) != 1) {
        logMsg("client TLS handshake fail: " + host);
        SSL_free(cssl); delete bd; return;
    }

    // 4. 진짜 서버로 TCP + [세션2] TLS handshake — *내가 클라役*
    SOCKET upstream = ConnectUpstream(host.c_str(), portStr.c_str());
    if (upstream == INVALID_SOCKET) {
        logMsg("upstream connect fail: " + target);
        SSL_free(cssl); delete bd; return;
    }
    setRecvTimeout(upstream, RECV_TIMEOUT_MS);

    SSL* ussl = SSL_new(g_clientCtx);
    SSL_set_fd(ussl, (int)upstream);
    SSL_set_tlsext_host_name(ussl, host.c_str());            // SNI
    SSL_set1_host(ussl, host.c_str());                       // 검증 시 호스트명 매칭(아래 verify 참고)
    if (SSL_connect(ussl) != 1) {
        logMsg("upstream TLS handshake fail: " + host);
        SSL_free(ussl); closesocket(upstream);
        SSL_free(cssl); delete bd; return;
    }

    logMsg("MITM " + target + " established (decrypting)");

    // 5. 평문 keep-alive 루프 — 같은 M2 파서가 '복호화된' HTTP 를 처리
    TlsStream cStream(cssl), uStream(ussl);
    SockReader cReader(&cStream), uReader(&uStream);
    while (true) {
        bool closeAfter = false;
        if (!proxyExchange("MITM", cReader, &cStream, uReader, &uStream, host, closeAfter)) break;
        if (closeAfter) break;
    }

    // 6. 정리
    SSL_shutdown(cssl); SSL_shutdown(ussl);
    SSL_free(cssl); SSL_free(ussl);
    closesocket(upstream);
    delete bd;
    logMsg("MITM " + target + " closed");
}


// ============================================================
//  HandleClient: 평문 HTTP(M2) + CONNECT(MITM) 분기
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

        // ---- CONNECT = HTTPS -> MITM ----
        if (method == "CONNECT") {
            if (upstream != INVALID_SOCKET) { closesocket(upstream); upstream = INVALID_SOCKET; up.reset(); upRaw.reset(); }
            // SockReader 가 CONNECT 헤드를 읽다 미리 읽어둔 잉여(=ClientHello 시작)를 넘긴다.
            std::string pre = client.takeBuffered();
            HandleConnectMITM(clientSock, client, uri, std::move(pre));
            closesocket(clientSock);
            return;
        }

        // ---- 평문 HTTP (M2 그대로) ----
        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) { sendRawSimple(clientSock, "400 Bad Request"); break; }
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0; std::string err;
        BodyMode reqMode = requestBodyMode(req, reqLen, err);
        if (reqMode == BodyMode::Error) { sendRawSimple(clientSock, "400 Bad Request"); break; }

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
        if (reqMode == BodyMode::Length) { if (!client.forwardExact((size_t)reqLen, upRaw.get())) break; }
        else if (reqMode == BodyMode::Chunked) { if (!client.forwardChunked(upRaw.get())) break; }

        HttpHead resp;
        if (!readHead(*up, resp)) { sendRawSimple(clientSock, "502 Bad Gateway"); break; }
        int status = parseStatus(resp.startLine);

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
        printf("[proxy_v4] Root CA 로드 실패 — docs/m4-mitm-setup.md 보고 rootCA.crt/key 준비\n");
        return false;
    }

    g_clientCtx = SSL_CTX_new(TLS_client_method());
    if (!g_clientCtx) return false;
    SSL_CTX_set_min_proto_version(g_clientCtx, TLS1_2_VERSION);
    // [PoC] upstream 인증서 검증 생략 — 제품에선 반드시 켜야 함(아래 한계 블록).
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

    printf("[proxy_v4] %d listening... (HTTP + HTTPS MITM decrypt)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;
        std::thread(HandleClient, clientSock).detach();
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);  // 로그를 실시간으로(버퍼링 끔) — 파일/파이프로 봐도 바로 보이게
    RunServer();
    return 0;
}


/*
============================================================
 v4 (MITM) 의 알려진 한계 (보고서에 기록)
============================================================
 - [보안] upstream(진짜 서버) 인증서 검증을 PoC 라 SSL_VERIFY_NONE 으로 끔.
   => 제품은 시스템 CA 번들로 SSL_CTX_set_verify(PEER) + 실패 시 차단/기록 필수.
      (지금 코드는 SSL_set1_host 로 호스트명만 세팅해 둠 — verify 켜면 매칭됨)
 - 인증서 신뢰: 브라우저가 우리 leaf 를 믿으려면 Root CA 가 OS/브라우저 신뢰
   저장소에 등록돼 있어야 한다(설정 단계). 안 하면 인증서 경고가 뜬다.
 - HSTS / 인증서 피닝 사이트(예: 일부 구글 도메인, 뱅킹앱)는 MITM 이 의도적으로
   실패한다. => 제품은 'raw 터널 fallback'(v3 처럼) 또는 bypass 목록 필요.
 - HTTP/2 · HTTP/3(QUIC) 미지원. ALPN 으로 h2 협상되면 이 HTTP/1.x 파서로는 깨진다.
   => ALPN 을 h2 로 광고하지 않거나(현재), h2 프레이밍 파서가 별도로 필요.
 - leaf 인증서 키 1개 공유 + SSL_CTX host 별 캐시는 메모리에 계속 쌓인다(PoC 수준).
 - 동시성: 연결당 스레드 2개(평문 경로는 1개). 대규모는 IOCP 가 맞음.
 - (M2/M3 한계 승계) absolute-form URI, hop-by-hop 헤더 정규화, Expect:100-continue,
   IPv6 host:port 등 미처리.

 [다음(M6~M7)] 이제 복호화된 평문이 proxyExchange 를 통과하므로,
   그 안에서 요청 헤더(Content-Type: multipart/form-data 등)와 body 를 들여다보면
   '파일 업로드 식별/추출'로 자연스럽게 확장된다. 그게 본 과제의 진짜 목표.
============================================================
*/
