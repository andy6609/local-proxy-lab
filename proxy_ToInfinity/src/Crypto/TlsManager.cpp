#include "Crypto/TlsManager.h"
#include "Core/Logger.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <map>
#include <mutex>

namespace proxy {

static const unsigned char ALPN_HTTP11[] = { 8, 'h','t','t','p','/','1','.','1' };

// 브라우저 ↔ 프록시 세션에서 브라우저가 h2를 제안해도 무조건 http/1.1로 다운그레이드
static int alpnSelectHttp11(SSL*, const unsigned char** out, unsigned char* outlen,
                            const unsigned char* in, unsigned int inlen, void*) {
    if (SSL_select_next_proto((unsigned char**)out, outlen,
                              ALPN_HTTP11, sizeof(ALPN_HTTP11), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// 동적 인증서(Leaf Cert) 발급 및 캐싱 관리
class CertAuthority {
    X509*      caCert_  = nullptr;
    EVP_PKEY*  caKey_   = nullptr;
    EVP_PKEY*  leafKey_ = nullptr;
    std::mutex mtx_;
    std::map<std::string, SSL_CTX*> cache_;

public:
    bool load(const char* caCertPath, const char* caKeyPath) {
        BIO* bc = BIO_new_file(caCertPath, "rb");
        if (!bc) { Logger::error(std::string("CA cert open fail: ") + caCertPath); return false; }
        caCert_ = PEM_read_bio_X509(bc, nullptr, nullptr, nullptr);
        BIO_free(bc);

        BIO* bk = BIO_new_file(caKeyPath, "rb");
        if (!bk) { Logger::error(std::string("CA key open fail: ") + caKeyPath); return false; }
        caKey_ = PEM_read_bio_PrivateKey(bk, nullptr, nullptr, nullptr);
        BIO_free(bk);

        if (!caCert_ || !caKey_) { Logger::error("CA cert/key parse fail"); return false; }

        leafKey_ = EVP_RSA_gen(2048);
        if (!leafKey_) { Logger::error("leaf key gen fail"); return false; }
        return true;
    }

    void cleanup() {
        if (caCert_) X509_free(caCert_);
        if (caKey_) EVP_PKEY_free(caKey_);
        if (leafKey_) EVP_PKEY_free(leafKey_);
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& kv : cache_) {
            SSL_CTX_free(kv.second);
        }
        cache_.clear();
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
        SSL_CTX_set_alpn_select_cb(ctx, alpnSelectHttp11, nullptr); // ALPN: 강제 HTTP/1.1
        
        if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, leafKey_) != 1 ||
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(caCert_)) != 1) {
            Logger::error("server ctx cert setup fail for " + host);
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
            Logger::error("leaf sign fail for " + host);
            X509_free(x); return nullptr;
        }
        return x;
    }

    static void addExt(X509* x, X509V3_CTX* ctx, int nid, const char* value) {
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
        if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    }
};

static CertAuthority g_ca;
static SSL_CTX* g_upstreamCtx = nullptr;

bool TlsManager::init() {
    if (!g_ca.load("rootCA.crt", "rootCA.key")) {
        Logger::error("Failed to load root CA. Ensure rootCA.crt and rootCA.key exist in the runtime directory.");
        return false;
    }

    g_upstreamCtx = SSL_CTX_new(TLS_client_method());
    if (!g_upstreamCtx) {
        Logger::error("Failed to create upstream SSL_CTX");
        return false;
    }
    
    // PoC 목적상 업스트림 인증서 검증은 생략
    SSL_CTX_set_verify(g_upstreamCtx, SSL_VERIFY_NONE, nullptr);
    Logger::info("TlsManager initialized successfully.");
    return true;
}

void TlsManager::cleanup() {
    g_ca.cleanup();
    if (g_upstreamCtx) {
        SSL_CTX_free(g_upstreamCtx);
        g_upstreamCtx = nullptr;
    }
}

SSL_CTX* TlsManager::getClientCtx(const std::string& host) {
    return g_ca.serverCtxForHost(host);
}

SSL_CTX* TlsManager::getUpstreamCtx() {
    return g_upstreamCtx;
}

} // namespace proxy
