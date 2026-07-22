#include "Protocol/Http1Engine.h"
#include "Protocol/Http2Engine.h"
#include "Core/Logger.h"
#include "Crypto/TlsManager.h"
#include "Inspector/TrafficAnalyzer.h"

#include <string>
#include <vector>
#include <algorithm>

namespace proxy {

// ============================================================
// 유틸리티 및 I/O 추상화
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
// 안전한 정수 파싱 (std::stoll/stoi 는 비정상 입력에 예외를 던져 detached 스레드를 죽인다).
// 순수 10진수만 허용, 실패 시 false. (선행 공백/탭은 무시)
static bool parseLL(const std::string& in, long long& out) {
    std::string t = in; trim(t);
    if (t.empty()) return false;
    long long v = 0;
    for (char c : t) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > (1LL << 40)) return false;
    }
    out = v; return true;
}

class Stream {
public:
    virtual ~Stream() {}
    virtual int read(char* buf, int len) = 0;
    virtual bool writeAll(const char* data, size_t len) = 0;
};

class SockStream : public Stream {
    SOCKET sock;
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
};

class TlsStream : public Stream {
    SSL* ssl;
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
};

class SockReader {
    Stream* src;
    std::string buffer;
    size_t off = 0;
    static const size_t IO_CHUNK = 16384;
    static const size_t MAX_HEAD_BYTES = 64 * 1024;
    
    void compact() {
        if (off == buffer.size()) { buffer.clear(); off = 0; }
        else if (off > 65536)     { buffer.erase(0, off); off = 0; }
    }
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

    bool forwardExact(size_t n, Stream* dest, std::string* cap = nullptr) {
        const size_t UPLOAD_CAP = 256 * 1024;
        while (n > 0) {
            if (off < buffer.size()) {
                size_t avail = (std::min)(n, buffer.size() - off);
                if (!dest->writeAll(buffer.data() + off, avail)) return false;
                if (cap && cap->size() < UPLOAD_CAP)
                    cap->append(buffer.data() + off, (std::min)(avail, UPLOAD_CAP - cap->size()));
                off += avail; n -= avail;
                compact();
            } else {
                if (!fill()) return false;
            }
        }
        return true;
    }

    bool forwardUntilClose(Stream* dest, std::string* cap = nullptr) {
        const size_t CAP = 256 * 1024;   // 응답 캡처 상한 (무제한 축적 방지)
        if (off < buffer.size()) {
            size_t avail = buffer.size() - off;
            if (!dest->writeAll(buffer.data() + off, avail)) return false;
            if (cap && cap->size() < CAP) cap->append(buffer.data() + off, (std::min)(avail, CAP - cap->size()));
            off = buffer.size(); compact();
        }
        char tmp[IO_CHUNK];
        while (true) {
            int n = src->read(tmp, sizeof(tmp));
            if (n <= 0) break;
            if (!dest->writeAll(tmp, (size_t)n)) return false;
            if (cap && cap->size() < CAP) cap->append(tmp, (std::min)((size_t)n, CAP - cap->size()));
        }
        return true;
    }

    bool forwardChunked(Stream* dest, std::string* cap = nullptr) {
        while (true) {
            std::string line;
            if (!readLine(line)) return false;
            
            long long sz = 0;
            for (char c : line) {
                int d = -1;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else break;
                sz = sz * 16 + d;
            }

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

    std::string takeBuffered() {
        std::string s = buffer.substr(off);
        buffer.clear(); off = 0;
        return s;
    }
};

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
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        trim(name); trim(value);
        head.headers.push_back({name, value});
    }
    return true;
}

enum class BodyMode { None, Length, Chunked, UntilClose, Error };

static BodyMode requestBodyMode(const HttpHead& h, long long& clen) {
    std::string cl = headerGet(h, "content-length");
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (!te.empty() && te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    if (!cl.empty() && parseLL(cl, clen)) return BodyMode::Length;
    return BodyMode::None;
}

static BodyMode responseBodyMode(const HttpHead& h, int status, long long& clen) {
    if ((status >= 100 && status < 200) || status == 204 || status == 304) return BodyMode::None;
    std::string te = toLower(headerGet(h, "transfer-encoding"));
    if (!te.empty() && te.find("chunked") != std::string::npos) return BodyMode::Chunked;
    std::string cl = headerGet(h, "content-length");
    if (!cl.empty() && parseLL(cl, clen)) return BodyMode::Length;
    return BodyMode::UntilClose;
}

static SOCKET connectUpstreamTcp(const std::string& host, int port) {
    struct addrinfo hints = {}, *info = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &info) != 0) return INVALID_SOCKET;

    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock != INVALID_SOCKET) {
        if (connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock); sock = INVALID_SOCKET;
        }
    }
    freeaddrinfo(info);
    return sock;
}

// ============================================================
// 엔진 메인 로직
// ============================================================
void Http1Engine::process(Context& ctx) {
    SockStream plainSock(ctx.clientSock);
    SockReader plainReader(&plainSock);

    HttpHead connReq;
    if (!readHead(plainReader, connReq)) return;

    // HTTP 프록시의 시작은 CONNECT 이어야 함 (투명 프록시는 향후 WFP 연동 시 구현)
    if (connReq.startLine.find("CONNECT") != 0) {
        Logger::warn("Not a CONNECT request. Dropping.");
        return;
    }

    size_t s1 = connReq.startLine.find(' ');
    size_t s2 = connReq.startLine.find(' ', s1 + 1);
    std::string hp = connReq.startLine.substr(s1 + 1, s2 - s1 - 1);
    size_t c = hp.find(':');
    ctx.targetHost = hp.substr(0, c);
    ctx.targetPort = 443;
    if (c != std::string::npos) { long long p; if (parseLL(hp.substr(c + 1), p) && p > 0 && p < 65536) ctx.targetPort = (int)p; }

    // CONNECT 성공 응답 (이걸 받아야 클라가 ClientHello 를 보냄)
    plainSock.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n", 39);

    // 1. [FIX] 클라이언트측 TLS 를 먼저 (내가 서버役) → 클라의 ALPN(h2/1.1)을 알아낸다.
    //    업스트림보다 먼저 해야 업스트림에 '같은 프로토콜'만 제안해 h2↔1.1 불일치를 막는다.
    SSL_CTX* cCtx = TlsManager::getClientCtx(ctx.targetHost);
    if (!cCtx) return;
    ctx.clientSsl = SSL_new(cCtx);
    SSL_set_fd(ctx.clientSsl, (int)ctx.clientSock);
    if (SSL_accept(ctx.clientSsl) <= 0) {
        Logger::error("Client SSL_accept failed (possibly ALPN fallback rejected)");
        return;
    }
    const unsigned char* alpnData = nullptr;
    unsigned int alpnLen = 0;
    SSL_get0_alpn_selected(ctx.clientSsl, &alpnData, &alpnLen);
    ctx.isClientHttp2 = (alpnLen == 2 && memcmp(alpnData, "h2", 2) == 0);

    // 2. 업스트림 연결 + [FIX] 클라와 같은 ALPN 만 광고.
    //    (업스트림이 h2 를 고르는데 우리가 1.1 텍스트를 쏴서 응답이 안 오던 버그 방지)
    ctx.upstreamSock = connectUpstreamTcp(ctx.targetHost, ctx.targetPort);
    if (ctx.upstreamSock == INVALID_SOCKET) {
        Logger::error("Failed to connect to upstream: " + ctx.targetHost);
        return;
    }
    static const unsigned char ALPN_H2_ONLY[]     = { 2, 'h','2' };
    static const unsigned char ALPN_HTTP11_ONLY[] = { 8, 'h','t','t','p','/','1','.','1' };
    ctx.upstreamSsl = SSL_new(TlsManager::getUpstreamCtx());
    SSL_set_tlsext_host_name(ctx.upstreamSsl, ctx.targetHost.c_str());
    if (ctx.isClientHttp2) SSL_set_alpn_protos(ctx.upstreamSsl, ALPN_H2_ONLY, sizeof(ALPN_H2_ONLY));
    else                   SSL_set_alpn_protos(ctx.upstreamSsl, ALPN_HTTP11_ONLY, sizeof(ALPN_HTTP11_ONLY));
    SSL_set_fd(ctx.upstreamSsl, (int)ctx.upstreamSock);
    if (SSL_connect(ctx.upstreamSsl) <= 0) {
        Logger::error("Upstream SSL_connect failed");
        return;
    }
    const unsigned char* uAlpn = nullptr;
    unsigned int uAlpnLen = 0;
    SSL_get0_alpn_selected(ctx.upstreamSsl, &uAlpn, &uAlpnLen);
    ctx.isUpstreamHttp2 = (uAlpnLen == 2 && memcmp(uAlpn, "h2", 2) == 0);

    // 3. 분기
    if (ctx.isClientHttp2) {
        Logger::info("ALPN Negotiated: h2 for " + ctx.targetHost);
        Http2Engine::process(ctx);
        return; // HTTP/2 처리는 Http2Engine에 위임하고 종료
    }
    Logger::info("ALPN Negotiated: http/1.1 for " + ctx.targetHost);

    TlsStream clientStream(ctx.clientSsl);
    TlsStream upstreamStream(ctx.upstreamSsl);
    SockReader cReader(&clientStream);
    SockReader uReader(&upstreamStream);

    Logger::info("MITM Established: " + ctx.targetHost);

    // 4. HTTP/1.1 통신 루프 (Keep-Alive)
    while (true) {
        HttpHead req;
        if (!readHead(cReader, req)) break;

        size_t methodEnd = req.startLine.find(' ');
        std::string method = req.startLine.substr(0, methodEnd);
        // 요청 라인에서 경로(URI)도 뽑는다 — 분석기 라우팅/서비스 지문(예: /backend-api/files)용
        std::string reqUri = "/";
        if (methodEnd != std::string::npos) {
            size_t uriEnd = req.startLine.find(' ', methodEnd + 1);
            reqUri = req.startLine.substr(methodEnd + 1,
                        (uriEnd == std::string::npos ? req.startLine.size() : uriEnd) - (methodEnd + 1));
        }

        long long reqLen = 0;
        BodyMode reqMode = requestBodyMode(req, reqLen);
        
        // [9번] 이전엔 Accept-Encoding 을 지워 압축을 '회피'했으나, 이제 그대로 두고
        //       응답을 실제로 해제한다(analyzeResponse 의 decodeBody). 클라로는 압축 그대로 전달.

        std::string reqBodyCap;
        std::string* reqCapPtr = &reqBodyCap; // 항상 캡처하여 TrafficAnalyzer에 전달

        // 요청 전달
        std::string headOut = serializeHead(req);
        if (!upstreamStream.writeAll(headOut.data(), headOut.size())) break;
        if (reqMode == BodyMode::Length) { if (!cReader.forwardExact((size_t)reqLen, &upstreamStream, reqCapPtr)) break; }
        else if (reqMode == BodyMode::Chunked) { if (!cReader.forwardChunked(&upstreamStream, reqCapPtr)) break; }

        // [연구 영역] 분석기 호출 (url 인자에는 host 가 아니라 요청 경로를 넘긴다)
        TrafficAnalyzer::analyzeRequest(method, reqUri, headOut, reqBodyCap);

        // 응답 수신
        HttpHead resp;
        if (!readHead(uReader, resp)) break;
        
        int status = 0;
        size_t sStart = resp.startLine.find(' ');
        if (sStart != std::string::npos) {
            size_t sEnd = resp.startLine.find(' ', sStart + 1);
            std::string st = resp.startLine.substr(sStart + 1,
                                (sEnd == std::string::npos ? resp.startLine.size() : sEnd) - (sStart + 1));
            long long sv; if (parseLL(st, sv)) status = (int)sv;
        }

        long long respLen = 0;
        BodyMode respMode = responseBodyMode(resp, status, respLen);

        std::string respBodyCap;
        std::string* respCapPtr = &respBodyCap;

        // 응답 전달
        std::string respHeadOut = serializeHead(resp);
        if (!clientStream.writeAll(respHeadOut.data(), respHeadOut.size())) break;
        
        bool serverClosed = false;
        if (respMode == BodyMode::Length) { if (!uReader.forwardExact((size_t)respLen, &clientStream, respCapPtr)) break; }
        else if (respMode == BodyMode::Chunked) { if (!uReader.forwardChunked(&clientStream, respCapPtr)) break; }
        else if (respMode == BodyMode::UntilClose) { uReader.forwardUntilClose(&clientStream, respCapPtr); serverClosed = true; }

        // [연구 영역] 분석기 호출
        TrafficAnalyzer::analyzeResponse(status, respHeadOut, respBodyCap);

        // Keep-Alive 판정
        std::string reqConn = toLower(headerGet(req, "connection"));
        std::string respConn = toLower(headerGet(resp, "connection"));
        if (serverClosed || reqConn == "close" || respConn == "close") break;
    }
}

} // namespace proxy
