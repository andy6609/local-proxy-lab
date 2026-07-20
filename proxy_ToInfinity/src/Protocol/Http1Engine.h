#ifndef PROXY_HTTP1_ENGINE_H
#define PROXY_HTTP1_ENGINE_H

#include "Core/Context.h"

namespace proxy {

class Http1Engine {
public:
    // HTTP/1.1 프록시 통신 루프 처리 (Keep-Alive 지원)
    static void process(Context& ctx);
};

} // namespace proxy

#endif // PROXY_HTTP1_ENGINE_H
