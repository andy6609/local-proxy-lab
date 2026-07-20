#include <iostream>
#include "Core/Logger.h"
#include "Core/ProxyServer.h"
#include "Crypto/TlsManager.h"

int main() {
    proxy::Logger::init(proxy::Logger::Level::DEBUG);
    proxy::Logger::info("proxy_ToInfinity starting...");
    
    if (!proxy::TlsManager::init()) {
        proxy::Logger::error("TlsManager init failed");
        return 1;
    }

    proxy::ProxyServer server(18080);
    server.start();

    proxy::TlsManager::cleanup();
    proxy::Logger::info("Server stopped.");
    return 0;
}
