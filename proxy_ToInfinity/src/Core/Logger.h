#ifndef PROXY_LOGGER_H
#define PROXY_LOGGER_H

#include <string>

namespace proxy {

class Logger {
public:
    enum class Level {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    static void init(Level level = Level::INFO);
    static void log(Level level, const std::string& msg);
    static void debug(const std::string& msg);
    static void info(const std::string& msg);
    static void warn(const std::string& msg);
    static void error(const std::string& msg);
};

} // namespace proxy

#endif // PROXY_LOGGER_H
