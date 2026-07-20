#ifndef PROXY_HTTP2_ENGINE_H
#define PROXY_HTTP2_ENGINE_H

#include "Core/Context.h"

namespace proxy {

class Http2Engine {
public:
    // nghttp2 기반 브릿지 처리
    static void process(Context& ctx);
};

} // namespace proxy

#endif // PROXY_HTTP2_ENGINE_H
