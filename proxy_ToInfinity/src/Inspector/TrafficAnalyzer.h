#ifndef PROXY_TRAFFIC_ANALYZER_H
#define PROXY_TRAFFIC_ANALYZER_H

#include <string>

namespace proxy {

// 이 클래스가 앞으로 파일 업로드 분석, multipart 파싱, 매직넘버 검사를 담당합니다.
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
};

} // namespace proxy

#endif // PROXY_TRAFFIC_ANALYZER_H
