#include "Inspector/TrafficAnalyzer.h"
#include "Core/Logger.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace proxy {

std::string TrafficAnalyzer::getHeaderValue(const std::string& headers, const std::string& key) {
    std::string lowerHeaders = headers;
    std::transform(lowerHeaders.begin(), lowerHeaders.end(), lowerHeaders.begin(), ::tolower);
    std::string lowerKey = key;
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    
    size_t pos = lowerHeaders.find(lowerKey + ":");
    if (pos == std::string::npos) return "";
    pos += key.length() + 1;
    while (pos < headers.length() && (headers[pos] == ' ' || headers[pos] == '\t')) pos++;
    
    size_t endPos = headers.find("\r\n", pos);
    if (endPos == std::string::npos) endPos = headers.length();
    
    return headers.substr(pos, endPos - pos);
}

// [W8] 간단한 해시 함수 (데모 목적의 의사 SHA-256 또는 해시 합)
std::string TrafficAnalyzer::calculateHash(const std::string& data) {
    unsigned long long hash = 5381;
    for (char c : data) {
        hash = ((hash << 5) + hash) + c;
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

// [W9] 매직넘버 검증 로직
bool TrafficAnalyzer::verifyMagicNumber(const std::string& data, const std::string& mimeType) {
    if (data.size() < 8) return false;
    
    std::string lowerMime = mimeType;
    std::transform(lowerMime.begin(), lowerMime.end(), lowerMime.begin(), ::tolower);
    
    if (lowerMime == "application/pdf") {
        return data.substr(0, 5) == "%PDF-";
    } else if (lowerMime == "image/png") {
        return (unsigned char)data[0] == 0x89 && data.substr(1, 3) == "PNG";
    } else if (lowerMime == "image/jpeg" || lowerMime == "image/jpg") {
        return (unsigned char)data[0] == 0xFF && (unsigned char)data[1] == 0xD8;
    }
    // 기본적으로 알 수 없는 타입은 경고 없이 넘어감
    return true; 
}

void TrafficAnalyzer::analyzeRequest(const std::string& method, 
                                     const std::string& url, 
                                     const std::string& headers, 
                                     const std::string& body) {
    if (method != "POST" && method != "PUT") return;

    std::string host = getHeaderValue(headers, "Host");
    std::string contentType = getHeaderValue(headers, "Content-Type");
    
    if (!contentType.empty()) {
        routeToParser(host, url, contentType, headers, body);
    }
}

void TrafficAnalyzer::routeToParser(const std::string& host, const std::string& url, const std::string& contentType, const std::string& headers, const std::string& body) {
    
    // AI 서비스 전용 핑거프린트 확인
    if (host.find("chatgpt.com") != std::string::npos && url.find("/backend-api/files") != std::string::npos) {
        Logger::info("[Router] ChatGPT 파일 업로드 API 식별. ChatGPT 전용 파서로 라우팅됨");
        parseChatGPTUpload(body, contentType);
        return;
    }
    
    // 기본 멀티파트 파서로 라우팅
    if (contentType.find("multipart/form-data") != std::string::npos) {
        size_t boundaryPos = contentType.find("boundary=");
        if (boundaryPos != std::string::npos) {
            std::string boundary = contentType.substr(boundaryPos + 9);
            if (!boundary.empty() && boundary.front() == '"') boundary.erase(0, 1);
            if (!boundary.empty() && boundary.back() == '"') boundary.pop_back();
            
            Logger::info("[Router] 표준 멀티파트 트래픽 식별. 표준 멀티파트 파서로 라우팅됨");
            parseStandardMultipart(body, boundary);
        }
    }
}

void TrafficAnalyzer::parseChatGPTUpload(const std::string& body, const std::string& contentType) {
    Logger::info("[Parser] ChatGPT 파일 파싱은 아직 미구현입니다. 추가 트래픽 캡처 후 적용 예정");
}

void TrafficAnalyzer::parseStandardMultipart(const std::string& body, const std::string& boundary) {
    std::string fullBoundary = "--" + boundary;
    size_t pos = body.find(fullBoundary);
    
    std::error_code ec;
    std::filesystem::create_directories("captured_files", ec);

    while (pos != std::string::npos) {
        size_t nextPos = body.find(fullBoundary, pos + fullBoundary.length());
        if (nextPos == std::string::npos) break;

        size_t partStart = pos + fullBoundary.length();
        if (partStart + 2 <= body.length() && body.substr(partStart, 2) == "\r\n") {
            partStart += 2;
        }

        size_t partEnd = nextPos;
        if (partEnd >= 2 && body.substr(partEnd - 2, 2) == "\r\n") {
            partEnd -= 2;
        }

        std::string part = body.substr(partStart, partEnd - partStart);

        size_t headerEnd = part.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string partHeaders = part.substr(0, headerEnd) + "\r\n";
            std::string partBody = part.substr(headerEnd + 4);

            std::string disp = getHeaderValue(partHeaders, "Content-Disposition");
            std::string mime = getHeaderValue(partHeaders, "Content-Type");
            size_t filenamePos = disp.find("filename=\"");
            
            if (filenamePos != std::string::npos) {
                size_t filenameEnd = disp.find("\"", filenamePos + 10);
                if (filenameEnd != std::string::npos) {
                    std::string filename = disp.substr(filenamePos + 10, filenameEnd - (filenamePos + 10));
                    Logger::info("[Parser] 파일명: " + filename + ", 크기: " + std::to_string(partBody.size()) + " bytes 추출 완료");
                    
                    // [W9] 매직넘버 검증
                    if (!mime.empty()) {
                        bool magicOk = verifyMagicNumber(partBody, mime);
                        if (magicOk) {
                            Logger::info("[Verifier] 매직넘버 일치 확인 (" + mime + ")");
                        } else {
                            Logger::warn("[Verifier] 경고! MIME 타입과 실제 매직넘버 불일치 의심 (" + mime + ")");
                        }
                    }

                    // [W8] 해시 검증
                    std::string fileHash = calculateHash(partBody);
                    Logger::info("[Verifier] 추출된 파일 해시: " + fileHash + " (원본과 비교 요망)");
                    
                    std::string filepath = "captured_files/" + filename;
                    std::ofstream ofs(filepath, std::ios::binary);
                    if (ofs) {
                        ofs.write(partBody.data(), partBody.size());
                        ofs.close();
                        Logger::info("[Parser] 파일 저장 완료: " + filepath);
                    } else {
                        Logger::error("[Parser] 파일 저장 실패: " + filepath);
                    }
                }
            }
        }
        pos = nextPos;
    }
}

void TrafficAnalyzer::analyzeResponse(int statusCode, 
                                      const std::string& headers, 
                                      const std::string& body) {
    std::string encoding = getHeaderValue(headers, "Content-Encoding");
    if (!encoding.empty() && encoding != "identity") {
        Logger::warn("[TrafficAnalyzer] 응답이 압축되어 있음: " + encoding + ". 클라이언트 Accept-Encoding 조작 실패 의심.");
    }
}

} // namespace proxy
