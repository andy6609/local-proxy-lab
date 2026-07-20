#ifndef PROXY_TLS_MANAGER_H
#define PROXY_TLS_MANAGER_H

#include <string>
#include <openssl/ssl.h>

namespace proxy {

class TlsManager {
public:
    // OpenSSL 라이브러리 전역 초기화 및 Root CA 로드
    static bool init();
    
    // 전역 정리
    static void cleanup();

    // 클라이언트와 연결할 때 사용하는 서버용 SSL_CTX 반환 (동적 인증서 생성 포함)
    static SSL_CTX* getClientCtx(const std::string& host);
    
    // 실제 서버(Upstream)와 연결할 때 사용하는 클라이언트용 SSL_CTX 반환
    static SSL_CTX* getUpstreamCtx();
};

} // namespace proxy

#endif // PROXY_TLS_MANAGER_H
