#include <iostream>
#include "Core/Logger.h"

int main() {
    proxy::Logger::init(proxy::Logger::Level::DEBUG);
    proxy::Logger::info("proxy_ToInfinity starting...");
    
    // TODO: Initialize TlsManager
    // TODO: Start ProxyServer on port 18080

    proxy::Logger::info("Server stopped.");
    return 0;
}
