#include "Protocol/Http2Engine.h"
#include "Core/Logger.h"
#include "Inspector/TrafficAnalyzer.h"

#include <nghttp2/nghttp2.h>
#include <vector>
#include <map>
#include <algorithm>

namespace proxy {

static const size_t UPLOAD_CAPTURE_CAP = 256 * 1024;

// [BUG FIX] 매크로를 사용하여 리터럴 문자열의 주소를 안전하게 전달
// (기존의 임시 std::string 생성 후 파괴에 따른 Dangling Pointer 문제 해결)
#define MAKE_NV(NAME, VALUE) \
    {(uint8_t*)(NAME), (uint8_t*)(VALUE).c_str(), sizeof(NAME) - 1, (VALUE).size(), NGHTTP2_NV_FLAG_NONE}

struct H2Bridge;

struct H2Stream {
    int32_t cid = -1;
    int32_t uid = -1;
    H2Bridge* br = nullptr;

    std::string method, path, scheme, authority, ctype;
    std::vector<std::pair<std::string, std::string>> reqHdr;
    std::string reqBody;
    bool reqEof = false;
    bool reqSubmitted = false;

    std::vector<std::pair<std::string, std::string>> respHdr;
    std::string respBody;
    bool respEof = false;
    int status = 0;
    bool respSubmitted = false;

    bool isUpload = false;
    std::string uploadCap;
    bool uploadLogged = false;
};

struct H2Bridge {
    SSL* cssl = nullptr; SOCKET csock = INVALID_SOCKET; nghttp2_session* csess = nullptr;
    SSL* ussl = nullptr; SOCKET usock = INVALID_SOCKET; nghttp2_session* usess = nullptr;
    std::string host;
    std::map<int32_t, H2Stream*> byClient;
    std::map<int32_t, H2Stream*> byUpstream;
    std::vector<H2Stream*> all;
    bool cClosed = false, uClosed = false;

    H2Stream* newStream() { H2Stream* s = new H2Stream(); s->br = this; all.push_back(s); return s; }
};

static bool skipReqHeader(const std::string& lname) {
    return lname == "connection" || lname == "keep-alive" || lname == "proxy-connection" ||
           lname == "transfer-encoding" || lname == "upgrade" || lname == "host" || lname == "te" ||
           lname == "accept-encoding"; // [Phase 5] 압축 회피: 서버가 평문 응답을 보내도록 강제
}

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

static void submitUpstreamRequest(H2Bridge* br, H2Stream* s, bool hasBody) {
    std::vector<nghttp2_nv> nva;
    std::string scheme = s->scheme.empty() ? "https" : s->scheme;
    std::string authority = s->authority.empty() ? br->host : s->authority;
    
    // MAKE_NV 매크로를 사용하여 포인터를 안전하게 넘김
    nva.push_back(MAKE_NV(":method", s->method));
    nva.push_back(MAKE_NV(":scheme", scheme));
    nva.push_back(MAKE_NV(":path", s->path));
    nva.push_back(MAKE_NV(":authority", authority));
    
    for (auto& kv : s->reqHdr) {
        nghttp2_nv nv;
        nv.name = (uint8_t*)kv.first.c_str(); nv.namelen = kv.first.size();
        nv.value = (uint8_t*)kv.second.c_str(); nv.valuelen = kv.second.size();
        nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(nv);
    }

    nghttp2_data_provider prd; prd.source.ptr = s; prd.read_callback = reqBodyRead;
    int32_t uid = nghttp2_submit_request(br->usess, nullptr, nva.data(), nva.size(),
                                         hasBody ? &prd : nullptr, s);
    if (uid < 0) { Logger::error("nghttp2_submit_request failed"); return; }
    s->uid = uid; s->reqSubmitted = true;
    br->byUpstream[uid] = s;
}

static void submitClientResponse(H2Bridge* br, H2Stream* s, bool hasBody) {
    std::vector<nghttp2_nv> nva;
    std::string st = std::to_string(s->status ? s->status : 502);
    nva.push_back(MAKE_NV(":status", st));
    
    for (auto& kv : s->respHdr) {
        nghttp2_nv nv;
        nv.name = (uint8_t*)kv.first.c_str(); nv.namelen = kv.first.size();
        nv.value = (uint8_t*)kv.second.c_str(); nv.valuelen = kv.second.size();
        nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(nv);
    }

    nghttp2_data_provider prd; prd.source.ptr = s; prd.read_callback = respBodyRead;
    int rv = nghttp2_submit_response(br->csess, s->cid, nva.data(), nva.size(), hasBody ? &prd : nullptr);
    if (rv != 0) { Logger::error("nghttp2_submit_response failed"); return; }
    s->respSubmitted = true;
}

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

    if (session == br->csess) {   
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
    } else {                      
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
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
            if (!s) return 0;
            if (endStream) s->reqEof = true;
            submitUpstreamRequest(br, s, !endStream);
            
            // 본문이 없는 GET 요청인 경우 바로 분석기 호출
            if (endStream) {
                std::string hdrs = "Host: " + br->host + "\r\n";
                for (auto& kv : s->reqHdr) hdrs += kv.first + ": " + kv.second + "\r\n";
                TrafficAnalyzer::analyzeRequest(s->method, s->path, hdrs, "");
            }
        } else if (frame->hd.type == NGHTTP2_DATA && endStream) {
            H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
            if (s) {
                s->reqEof = true;
                if (s->uid >= 0) nghttp2_session_resume_data(br->usess, s->uid);
                std::string hdrs = "Host: " + br->host + "\r\n";
                for (auto& kv : s->reqHdr) hdrs += kv.first + ": " + kv.second + "\r\n";
                TrafficAnalyzer::analyzeRequest(s->method, s->path, hdrs, s->uploadCap);
            }
        }
    } else {
        if (frame->hd.type == NGHTTP2_HEADERS) {
            H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
            if (!s) return 0;
            if (endStream) s->respEof = true;
            submitClientResponse(br, s, !endStream);
            
            if (endStream) {
                TrafficAnalyzer::analyzeResponse(s->status, "H2-Headers", "");
            }
        } else if (frame->hd.type == NGHTTP2_DATA && endStream) {
            H2Stream* s = br->byUpstream.count(sid) ? br->byUpstream[sid] : nullptr;
            if (s) {
                s->respEof = true; 
                if (s->cid >= 0) nghttp2_session_resume_data(br->csess, s->cid);
                TrafficAnalyzer::analyzeResponse(s->status, "H2-Headers", "[Body Data Omitted for Log]");
            }
        }
    }
    return 0;
}

static int cb_on_data_chunk(nghttp2_session* session, uint8_t, int32_t sid,
                            const uint8_t* data, size_t len, void* user) {
    H2Bridge* br = (H2Bridge*)user;
    if (session == br->csess) {   
        H2Stream* s = (H2Stream*)nghttp2_session_get_stream_user_data(session, sid);
        if (!s) return 0;
        s->reqBody.append((const char*)data, len);
        if (s->uploadCap.size() < UPLOAD_CAPTURE_CAP)
            s->uploadCap.append((const char*)data, (std::min)(len, UPLOAD_CAPTURE_CAP - s->uploadCap.size()));
        if (s->uid >= 0) nghttp2_session_resume_data(br->usess, s->uid);
    } else {                      
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
}

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

static void setNonBlocking(SOCKET s) {
    setNonBlockingPlatform(s);
}

static bool pumpRecv(SSL* ssl, nghttp2_session* sess, bool& closed) {
    char buf[16384];
    for (;;) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            ssize_t rv = nghttp2_session_mem_recv(sess, (const uint8_t*)buf, (size_t)n);
            if (rv < 0) return false;
            continue;
        }
        int e = SSL_get_error(ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return true;
        closed = true;
        return true;
    }
}

void Http2Engine::process(Context& ctx) {
    H2Bridge br;
    br.cssl = ctx.clientSsl;
    br.csock = ctx.clientSock;
    br.ussl = ctx.upstreamSsl;
    br.usock = ctx.upstreamSock;
    br.host = ctx.targetHost;

    nghttp2_session_callbacks* scbs = makeCallbacks(true);
    nghttp2_session_server_new(&br.csess, scbs, &br);
    nghttp2_session_callbacks_del(scbs);

    nghttp2_session_callbacks* ccbs = makeCallbacks(false);
    nghttp2_session_client_new(&br.usess, ccbs, &br);
    nghttp2_session_callbacks_del(ccbs);

    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
    nghttp2_submit_settings(br.csess, NGHTTP2_FLAG_NONE, iv, 1);
    nghttp2_submit_settings(br.usess, NGHTTP2_FLAG_NONE, iv, 1);

    setNonBlocking(br.csock);
    setNonBlocking(br.usock);

    Logger::info("H2Bridge running for " + br.host);

    for (;;) {
        if (nghttp2_session_send(br.csess) != 0) break;
        if (nghttp2_session_send(br.usess) != 0) break;

        bool cWR = nghttp2_session_want_read(br.csess) != 0;
        bool cWW = nghttp2_session_want_write(br.csess) != 0;
        bool uWR = nghttp2_session_want_read(br.usess) != 0;
        bool uWW = nghttp2_session_want_write(br.usess) != 0;

        if (br.cClosed && br.uClosed) break;
        if (!cWR && !cWW && !uWR && !uWW) break;

        fd_set rfds, wfds; FD_ZERO(&rfds); FD_ZERO(&wfds);
        if (!br.cClosed) FD_SET(br.csock, &rfds);
        if (!br.uClosed) FD_SET(br.usock, &rfds);
        if (cWW) FD_SET(br.csock, &wfds);
        if (uWW) FD_SET(br.usock, &wfds);

        timeval tv; tv.tv_sec = 30; tv.tv_usec = 0;
        int r = select(0, &rfds, &wfds, nullptr, &tv);
        if (r <= 0) break;

        if (FD_ISSET(br.csock, &rfds)) {
            if (!pumpRecv(br.cssl, br.csess, br.cClosed)) break;
        }
        if (FD_ISSET(br.usock, &rfds)) {
            if (!pumpRecv(br.ussl, br.usess, br.uClosed)) break;
        }
    }

    for (H2Stream* s : br.all) delete s;
    if (br.csess) nghttp2_session_del(br.csess);
    if (br.usess) nghttp2_session_del(br.usess);
    Logger::info("H2Bridge closed for " + br.host);
}

} // namespace proxy
