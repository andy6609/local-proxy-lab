#include "Inspector/TrafficAnalyzer.h"
#include "Core/Logger.h"

namespace proxy {

void TrafficAnalyzer::analyzeRequest(const std::string& method, 
                                     const std::string& url, 
                                     const std::string& headers, 
                                     const std::string& body) {
    // TODO: (W7) multipart/form-data 식별 및 boundary 파싱 로직 이식
    // TODO: (W8) 파일 추출 및 해시 검증 로직 구현
    
    // 현재는 로깅만 수행
    if (!body.empty()) {
        Logger::info("[TrafficAnalyzer] Request body captured: " + std::to_string(body.size()) + " bytes for " + method + " " + url);
    }
}

void TrafficAnalyzer::analyzeResponse(int statusCode, 
                                      const std::string& headers, 
                                      const std::string& body) {
    // TODO: (W9) Content-Encoding (zlib/brotli) 압축 해제 및 응답 분석 구현
    
    if (!body.empty()) {
        Logger::debug("[TrafficAnalyzer] Response body captured: " + std::to_string(body.size()) + " bytes, status=" + std::to_string(statusCode));
    }
}

} // namespace proxy
