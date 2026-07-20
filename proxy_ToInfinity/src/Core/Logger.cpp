#include "Core/Logger.h"
#include <iostream>
#include <mutex>

namespace proxy {

static Logger::Level g_logLevel = Logger::Level::INFO;
static std::mutex g_logMutex;

void Logger::init(Level level) {
    g_logLevel = level;
}

void Logger::log(Level level, const std::string& msg) {
    if (level < g_logLevel) return;

    std::lock_guard<std::mutex> lock(g_logMutex);
    switch (level) {
        case Level::DEBUG:   std::cout << "[DEBUG] "; break;
        case Level::INFO:    std::cout << "[INFO]  "; break;
        case Level::WARNING: std::cerr << "[WARN]  "; break;
        case Level::ERROR:   std::cerr << "[ERROR] "; break;
    }
    std::cout << msg << std::endl;
}

void Logger::debug(const std::string& msg) { log(Level::DEBUG, msg); }
void Logger::info(const std::string& msg)  { log(Level::INFO, msg); }
void Logger::warn(const std::string& msg)  { log(Level::WARNING, msg); }
void Logger::error(const std::string& msg) { log(Level::ERROR, msg); }

} // namespace proxy
