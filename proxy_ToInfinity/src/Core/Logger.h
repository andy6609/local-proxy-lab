#ifndef PROXY_LOGGER_H
#define PROXY_LOGGER_H

#include <string>

// Windows <wingdi.h>(via windows.h/winsock2.h)가 ERROR/DEBUG 를 매크로로 정의해
// enum 상수와 충돌한다. enum 선언 전에 undef 해서 식별자로 쓸 수 있게 한다.
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

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
