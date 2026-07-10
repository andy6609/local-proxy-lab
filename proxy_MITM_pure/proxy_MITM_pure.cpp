/*
============================================================
 proxy_MITM_pure — proxy_NoMITM 의 ★ 자리에 "순수 MITM" 을 채운 학습판
============================================================
 [무엇이 달라졌나 — NoMITM 과의 딱 두 가지 차이]
   1) 입출력을 Stream 으로 한 겹 추상화했다.
        - SockStream : recv/send           (평문 HTTP 경로)
        - TlsStream  : SSL_read/SSL_write   (복호화된 MITM 경로)
      => readHead/BodyMode/forward* 같은 HTTP 파서는 '한 줄도' 안 바뀌고
         평문이든 TLS 든 양쪽에서 그대로 재사용된다. (5주차 핵심 개념)
   2) HandleConnect 의 '그냥 통과(Relay ×2)' 자리를 TLS 양쪽 종단으로 바꿨다.
        브라우저 <== TLS 세션1 ==> [프록시] <== TLS 세션2 ==> 진짜 서버
                   (내가 서버役)             (내가 클라役)
      두 세션 사이에서 복호화된 평문이 흐르고, 그걸 4주차 파서가 읽는다.

 [5주차 커리큘럼 → 이 파일 어디]
   1  HTTPS 통신 구조            : HandleConnectMITM 전체 (HTTP 를 TLS 로 감싼 것)
   2  TLS Handshake 흐름         : SSL_accept(세션1) / SSL_connect(세션2)
   3  SNI 와 ALPN                : SSL_set_tlsext_host_name (SNI). ALPN 은 미사용(한계)
   4  인증서 기반 신뢰 검증       : g_clientCtx 의 VERIFY_NONE (PoC 라 끔 — 한계)
   5  Root/Intermediate/Leaf     : CertAuthority (Root 로드 + Leaf 발급. Intermediate 없음)
   6  Root CA 생성·설치          : 코드 밖(openssl CLI). 여기선 파일 로드만.
   7  Host 별 Leaf 동적 생성      : CertAuthority::makeLeaf
   8  TLS MITM 동작 원리          : HandleConnectMITM
   9  이중 TLS 세션 구조          : cssl(클라측) / ussl(서버측)
   10 Certificate Pinning        : 코드 대응 없음(개념). 핀닝 사이트는 세션1 이 실패함.

 [빌드/설정] rootCA.crt / rootCA.key 를 openssl 로 만들고 OS 신뢰저장소에 등록해야 함.
   자세힌 docs/m4-mitm-setup.md 참고.
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
#include <thread>
#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

static const int LISTEN_PORT = 18080;
static const int IO_CHUNK    = 16384;

// Root CA 파일 (openssl 로 생성 후 OS 신뢰저장소 등록). 절대경로 권장.
static const char* ROOT_CA_CERT = "rootCA.crt";
static const char* ROOT_CA_KEY  = "rootCA.key";


// ============================================================
//  공통 유틸
// ============================================================
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
//  Stream — 입출력 추상화 (★ NoMITM 대비 유일한 구조 변화)
//    파서는 Stream 만 알면 되고, 평문이든 TLS 든 똑같이 동작한다.
// ============================================================
class Stream {
public:
    virtual ~Stream() {}
    virtual int  read(char* buf, int len) = 0;            // <=0 이면 종료/에러
    virtual bool writeAll(const char* data, size_t len) = 0;
};

class SockStream : public Stream {                        // 평문 소켓
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

class TlsStream : public Stream {                         // 복호화된 TLS
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
//  SockReader — Stream 위의 버퍼드 리더 (로직은 NoMITM 과 동일)
// ============================================================
class SockReader {
public:
    explicit SockReader(Stream* s) : src(s) {}

    bool fill() {
        char tmp[IO_CHUNK];
        int n = src->read(tmp, sizeof(tmp));
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

    bool forwardExact(size_t n, Stream* dest) {
        while (n > 0) {
            if (off < internal.size()) {
                size_t avail = (std::min)(n, internal.size() - off);
                if (!dest->writeAll(internal.data() + off, avail)) return false;
                off += avail; n -= avail;
                compact();
            } else if (!fill()) return false;
        }
        return true;
    }

    bool forwardUntilClose(Stream* dest) {
        if (off < internal.size()) {
            if (!dest->writeAll(internal.data() + off, internal.size() - off)) return false;
            off = internal.size(); compact();
        }
        char tmp[IO_CHUNK];
        int n;
        while ((n = src->read(tmp, sizeof(tmp))) > 0)
            if (!dest->writeAll(tmp, (size_t)n)) return false;
        return true;
    }

    bool forwardChunked(Stream* dest) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;
            long long sz = strtoll(line.c_str(), nullptr, 16);   // 청크 크기는 16진수

            std::string sizeLine = line + "\r\n";
            if (!dest->writeAll(sizeLine.data(), sizeLine.size())) return false;

            if (sz == 0) {                                       // 0 = 끝
                std::string t;
                while (readLine(t)) {
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

    // CONNECT 헤드를 읽다 미리 읽힌(over-read) 잉여를 꺼내 비운다.
    //   MITM 에선 이게 '클라 ClientHello 의 시작분' -> SSL_accept 에 선주입해야 함.
    std::string takeBuffered() {
        std::string s = internal.substr(off);
        internal.clear(); off = 0;
        return s;
    }

private:
    void compact() {
        if (off == internal.size())  { internal.clear(); off = 0; }
        else if (off > 65536)        { internal.erase(0, off); off = 0; }
    }
    Stream* src;
    std::string internal;
    size_t off = 0;
};


// ============================================================
//  HTTP 헤드 + 파서 (NoMITM 과 동일 — TLS 와 무관)
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
//  upstream TCP 연결 (NoMITM 과 동일)
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
//  [MITM 1] Root CA 로드 + host 별 leaf 인증서 발급
//    5주차-5,6,7 : Root(로드) → Leaf(host 마다 즉석 발급)
//    학습판이라 캐시/락 없이 CONNECT 마다 새로 발급한다(느리지만 단순).
// ============================================================
class CertAuthority {
public:
    bool load(const char* caCertPath, const char* caKeyPath) {
        BIO* bc = BIO_new_file(caCertPath, "rb");            // fopen 대신 BIO (DLL 안전)
        if (!bc) return false;
        caCert_ = PEM_read_bio_X509(bc, nullptr, nullptr, nullptr);
        BIO_free(bc);

        BIO* bk = BIO_new_file(caKeyPath, "rb");
        if (!bk) return false;
        caKey_ = PEM_read_bio_PrivateKey(bk, nullptr, nullptr, nullptr);
        BIO_free(bk);

        if (!caCert_ || !caKey_) return false;

        leafKey_ = EVP_RSA_gen(2048);                        // 모든 leaf 가 공유하는 키 1개
        return leafKey_ != nullptr;
    }

    // host 용 서버 컨텍스트를 만든다. 반환한 ctx 는 호출자가 SSL_CTX_free 해야 함.
    SSL_CTX* serverCtxForHost(const std::string& host) {
        X509* leaf = makeLeaf(host);
        if (!leaf) return nullptr;

        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) { X509_free(leaf); return nullptr; }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, leafKey_) != 1 ||
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(caCert_)) != 1) {   // 체인에 CA 첨부
            X509_free(leaf); SSL_CTX_free(ctx); return nullptr;
        }
        X509_free(leaf);   // use_certificate 가 내부적으로 up-ref 함
        return ctx;
    }

private:
    // host(CN + SAN) 용 leaf 를 Root CA 로 서명해 발급. (5주차-7)
    X509* makeLeaf(const std::string& host) {
        X509* x = X509_new();
        if (!x) return nullptr;

        X509_set_version(x, 2);                              // v3

        unsigned char serial[8];                             // 랜덤 시리얼
        RAND_bytes(serial, sizeof(serial));
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
        BN_free(bn);

        X509_gmtime_adj(X509_getm_notBefore(x), -3600);          // 1시간 전
        X509_gmtime_adj(X509_getm_notAfter(x),  60L*60*24*825);  // ~825일

        X509_set_pubkey(x, leafKey_);

        X509_NAME* name = X509_get_subject_name(x);          // subject CN = host
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char*)host.c_str(), -1, -1, 0);
        X509_set_issuer_name(x, X509_get_subject_name(caCert_));  // issuer = CA

        X509V3_CTX ctx;                                      // v3 확장
        X509V3_set_ctx(&ctx, caCert_, x, nullptr, nullptr, 0);
        std::string san = "DNS:" + host;
        addExt(x, &ctx, NID_subject_alt_name, san.c_str());
        addExt(x, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        addExt(x, &ctx, NID_ext_key_usage, "serverAuth");
        addExt(x, &ctx, NID_subject_key_identifier, "hash");
        addExt(x, &ctx, NID_authority_key_identifier, "keyid,issuer");

        if (X509_sign(x, caKey_, EVP_sha256()) == 0) {       // Root CA 로 서명
            X509_free(x); return nullptr;
        }
        return x;
    }
    static void addExt(X509* x, X509V3_CTX* ctx, int nid, const char* value) {
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
        if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    }

    X509*     caCert_  = nullptr;
    EVP_PKEY* caKey_   = nullptr;
    EVP_PKEY* leafKey_ = nullptr;
};

static CertAuthority g_ca;
static SSL_CTX*      g_clientCtx = nullptr;   // upstream(진짜 서버)에 붙을 때 쓰는 클라 컨텍스트


// ============================================================
//  [MITM 2] pre-read 바이트를 SSL_accept 에 선주입하는 커스텀 BIO
//    CONNECT 뒤에 미리 읽힌 ClientHello 시작분(prefix)을 먼저 내보내고,
//    그 다음부터는 소켓에서 직접 recv. (보통 prefix 는 비어있음)
// ============================================================
struct PrefixBioData {
    SOCKET sock;
    std::string prefix;
    size_t off;
};
static int prefixBioRead(BIO* b, char* out, int len) {
    PrefixBioData* d = (PrefixBioData*)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (d->off < d->prefix.size()) {                         // 선주입 바이트 먼저
        int n = (std::min)(len, (int)(d->prefix.size() - d->off));
        memcpy(out, d->prefix.data() + d->off, n);
        d->off += (size_t)n;
        return n;
    }
    int n = recv(d->sock, out, len, 0);                      // 그 다음은 소켓에서
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
//  proxyExchange — 복호화된 평문 1회 교환 (4주차 파서를 Stream 위에서 그대로)
//    client(reader/out) <-> upstream(reader/out) 사이 요청 1개 + 응답 1개.
// ============================================================
static bool proxyExchange(SockReader& cr, Stream* cOut,
                          SockReader& ur, Stream* uOut,
                          const std::string& host, bool& closeAfter) {
    closeAfter = true;

    HttpHead req;                                            // 1. 요청 헤드 (복호화된 평문!)
    if (!readHead(cr, req)) return false;
    std::string method, uri, version;
    if (!parseRequestLine(req.startLine, method, uri, version)) return false;

    long long reqLen = 0;
    BodyMode reqMode = requestBodyMode(req, reqLen);

    std::string headOut = serializeHead(req);               // 2. 진짜 서버로 전달
    if (!uOut->writeAll(headOut.data(), headOut.size())) return false;
    if      (reqMode == BodyMode::Length)  { if (!cr.forwardExact((size_t)reqLen, uOut)) return false; }
    else if (reqMode == BodyMode::Chunked) { if (!cr.forwardChunked(uOut)) return false; }

    HttpHead resp;                                           // 3. 응답 헤드
    if (!readHead(ur, resp)) return false;
    int status = parseStatus(resp.startLine);

    std::string respOut = serializeHead(resp);              // 4. 브라우저로 전달
    if (!cOut->writeAll(respOut.data(), respOut.size())) return false;

    long long respLen = 0;
    BodyMode respMode = responseBodyMode(resp, method, status, respLen);
    bool serverClosed = false;
    if      (respMode == BodyMode::Length)     ur.forwardExact((size_t)respLen, cOut);
    else if (respMode == BodyMode::Chunked)    ur.forwardChunked(cOut);
    else if (respMode == BodyMode::UntilClose) { ur.forwardUntilClose(cOut); serverClosed = true; }

    // 5. ★ 여기서 HTTPS 의 평문 method/host/uri/status 가 보인다 (복호화 성공 증거)
    printf("[mitm] %-6s %s%s -> %d\n", method.c_str(), host.c_str(), uri.c_str(), status);

    closeAfter = serverClosed || wantsClose(req) || wantsClose(resp);
    return true;
}


// ============================================================
//  HandleConnectMITM — ★ NoMITM 의 'Relay ×2' 자리를 채운 MITM 본체
// ============================================================
static void HandleConnectMITM(SOCKET clientSock, const std::string& target, std::string preRead) {
    std::string host, port;
    splitHostPort(target, host, port, "443");

    // 1. 브라우저에 "터널 OK" — 이걸 받아야 브라우저가 ClientHello 를 보냄
    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSock, ok, (int)strlen(ok), 0);

    // 2. host 용 서버 컨텍스트(leaf 인증서) 발급
    SSL_CTX* sctx = g_ca.serverCtxForHost(host);
    if (!sctx) { closesocket(clientSock); return; }

    // 3. [세션1] 브라우저와 TLS — *내가 서버役* (가짜=내가 서명한 인증서)
    //    pre-read 로 들어온 ClientHello 시작분을 커스텀 BIO 로 선주입.
    SSL* cssl = SSL_new(sctx);
    BIO* cbio = BIO_new(g_prefixBioMethod);
    PrefixBioData* bd = new PrefixBioData{ clientSock, std::move(preRead), 0 };
    BIO_set_data(cbio, bd);
    BIO_set_init(cbio, 1);
    SSL_set_bio(cssl, cbio, cbio);
    if (SSL_accept(cssl) != 1) {
        printf("[mitm] client handshake fail: %s\n", host.c_str());
        SSL_free(cssl); SSL_CTX_free(sctx); delete bd; closesocket(clientSock); return;
    }

    // 4. [세션2] 진짜 서버로 TCP + TLS — *내가 클라役*
    SOCKET upstream = ConnectUpstream(host, port);
    if (upstream == INVALID_SOCKET) {
        SSL_free(cssl); SSL_CTX_free(sctx); delete bd; closesocket(clientSock); return;
    }
    SSL* ussl = SSL_new(g_clientCtx);
    SSL_set_fd(ussl, (int)upstream);
    SSL_set_tlsext_host_name(ussl, host.c_str());           // SNI (5주차-3)
    SSL_set1_host(ussl, host.c_str());
    if (SSL_connect(ussl) != 1) {
        printf("[mitm] upstream handshake fail: %s\n", host.c_str());
        SSL_free(ussl); closesocket(upstream);
        SSL_free(cssl); SSL_CTX_free(sctx); delete bd; closesocket(clientSock); return;
    }

    printf("[mitm] %s established (decrypting)\n", target.c_str());

    // 5. 복호화된 평문 keep-alive 루프 — 4주차 파서가 그대로 동작
    TlsStream cStream(cssl), uStream(ussl);
    SockReader cReader(&cStream), uReader(&uStream);
    while (true) {
        bool closeAfter = false;
        if (!proxyExchange(cReader, &cStream, uReader, &uStream, host, closeAfter)) break;
        if (closeAfter) break;
    }

    // 6. 정리
    SSL_shutdown(cssl); SSL_shutdown(ussl);
    SSL_free(cssl); SSL_free(ussl);
    SSL_CTX_free(sctx);
    closesocket(upstream);
    delete bd;
    closesocket(clientSock);
    printf("[mitm] %s closed\n", target.c_str());
}


// ============================================================
//  HandleClient — 요청 method 로 CONNECT(MITM) vs 평문 분기
//    한 함수 안에서 readHead 루프를 돌리고, 첫 줄이 CONNECT 면 MITM 으로 빠진다.
// ============================================================
static void HandleClient(SOCKET clientSock) {
    SockStream clientStream(clientSock);
    SockReader client(&clientStream);

    while (true) {
        HttpHead req;
        if (!readHead(client, req)) break;

        std::string method, uri, version;
        if (!parseRequestLine(req.startLine, method, uri, version)) break;

        // ---- CONNECT = HTTPS → MITM ----
        if (method == "CONNECT") {
            // CONNECT 헤드를 읽다 미리 읽힌 잉여(=ClientHello 시작)를 넘긴다.
            std::string pre = client.takeBuffered();
            HandleConnectMITM(clientSock, uri, std::move(pre));
            return;   // MITM 이 소켓을 닫고 끝냄
        }

        // ---- 평문 HTTP (NoMITM 과 동일, 단 Stream 사용) ----
        std::string hostHeader = headerGet(req, "host");
        if (hostHeader.empty()) break;
        std::string host, port;
        splitHostPort(hostHeader, host, port, "80");

        long long reqLen = 0;
        BodyMode reqMode = requestBodyMode(req, reqLen);

        SOCKET upstream = ConnectUpstream(host, port);
        if (upstream == INVALID_SOCKET) break;
        SockStream upStream(upstream);
        SockReader up(&upStream);

        std::string headOut = serializeHead(req);
        if (!upStream.writeAll(headOut.data(), headOut.size())) { closesocket(upstream); break; }
        if      (reqMode == BodyMode::Length)  client.forwardExact((size_t)reqLen, &upStream);
        else if (reqMode == BodyMode::Chunked) client.forwardChunked(&upStream);

        HttpHead resp;
        if (!readHead(up, resp)) { closesocket(upstream); break; }
        int status = parseStatus(resp.startLine);

        std::string respOut = serializeHead(resp);
        if (!clientStream.writeAll(respOut.data(), respOut.size())) { closesocket(upstream); break; }

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, method, status, respLen);
        bool serverClosed = false;
        if      (respMode == BodyMode::Length)     up.forwardExact((size_t)respLen, &clientStream);
        else if (respMode == BodyMode::Chunked)    up.forwardChunked(&clientStream);
        else if (respMode == BodyMode::UntilClose) { up.forwardUntilClose(&clientStream); serverClosed = true; }

        printf("[http] %-6s %s%s -> %d\n", method.c_str(), host.c_str(), uri.c_str(), status);
        closesocket(upstream);

        if (serverClosed || wantsClose(req) || wantsClose(resp)) break;
    }
    closesocket(clientSock);
}


// ============================================================
//  OpenSSL 초기화
// ============================================================
static bool InitTLS() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (!g_ca.load(ROOT_CA_CERT, ROOT_CA_KEY)) {
        printf("[proxy] Root CA 로드 실패 — rootCA.crt/key 준비 (docs/m4-mitm-setup.md)\n");
        return false;
    }

    g_clientCtx = SSL_CTX_new(TLS_client_method());
    if (!g_clientCtx) return false;
    SSL_CTX_set_min_proto_version(g_clientCtx, TLS1_2_VERSION);
    SSL_CTX_set_verify(g_clientCtx, SSL_VERIFY_NONE, nullptr);   // [PoC] upstream 검증 생략 (5주차-4 한계)

    g_prefixBioMethod = makePrefixBioMethod();
    return g_prefixBioMethod != nullptr;
}


// ============================================================
//  RunServer
// ============================================================
static void RunServer() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (!InitTLS()) { WSACleanup(); return; }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenSock, SOMAXCONN);
    printf("[proxy_MITM_pure] :%d  (HTTP + HTTPS MITM decrypt)\n", LISTEN_PORT);

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;
        std::thread(HandleClient, clientSock).detach();
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);   // 로그 실시간 출력
    RunServer();
    return 0;
}
