#ifndef PROXY_TRAFFIC_ANALYZER_H
#define PROXY_TRAFFIC_ANALYZER_H

#include <string>
#include <vector>

namespace proxy {

class TrafficAnalyzer {
public:
    // 클라이언트 -> 서버 방향의 요청을 가로채서 검사
    static void analyzeRequest(const std::string& method, 
                               const std::string& url, 
                               const std::string& headers, 
                               const std::string& body);

    // 서버 -> 클라이언트 방향의 응답을 가로채서 검사 (zlib 압축 해제 등)
    static void analyzeResponse(int statusCode, 
                                const std::string& headers, 
                                const std::string& body);
private:
    // 핑거프린트 기반 라우터
    static void routeToParser(const std::string& host, const std::string& url, const std::string& contentType, const std::string& headers, const std::string& body);

    // 공통 멀티파트 파서 (Standard)
    static void parseStandardMultipart(const std::string& body, const std::string& boundary);

    // AI 서비스 전용 커스텀 파서 (예시)
    static void parseChatGPTUpload(const std::string& body, const std::string& contentType);

    // 검증 유틸리티
    static std::string calculateHash(const std::string& data);
    static bool verifyMagicNumber(const std::string& data, const std::string& mimeType);
    static std::string getHeaderValue(const std::string& headers, const std::string& key);
};

} // namespace proxy

#endif // PROXY_TRAFFIC_ANALYZER_H
