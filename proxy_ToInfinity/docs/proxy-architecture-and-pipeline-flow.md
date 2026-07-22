# Local Proxy Architecture & Pipeline Deep Dive

이 문서는 `proxy_ToInfinity`의 내부 작동 구조, 트래픽 유입부터 파일 추출까지의 **전체 데이터 파이프라인**, 그리고 **호스트 필터(Host Filter)**와 **파서 라우팅(Parser Routing)**의 개념을 쉽게 이해할 수 있도록 설명합니다.

---

## 1. 전체 데이터 파이프라인 흐름 (Data Pipeline Flow)

프록시 서버는 클라이언트(브라우저/앱)와 진짜 AI 서버(업스트림) 사이에서 모든 트래픽을 가로채고 분석합니다.

```
[클라이언트 (App/Browser)]
       │  1. HTTP CONNECT / TCP 수신
       ▼
[ProxyServer (18080)] 
       │  2. TLS MITM (가짜 CA 인증서로 SSL_accept)
       ▼
[Http1Engine / Http2Engine]
       │  3. HTTP/1.1 또는 HTTP/2 프레임 디코딩 & 요청 조립
       ▼
[TrafficAnalyzer (핵심 분석 엔진)]
       ├── 4. [Observe] 모든 POST/PUT/PATCH 요청 화면 출력
       ├── 5. [Dumper]  호스트 필터링 (Target Host Check) ───► raw_dumps/*.txt 저장
       └── 6. [Router]  Content-Type / URL 기반 파서 분기 ───► captured_files/ 원본 파일 추출
       │  7. 진짜 서버로 데이터 전달 및 응답 중계
       ▼
[Upstream Server (OpenAI, Claude, Google 등)]
```

---

## 2. 호스트 필터링 (Host Filter List)이란?

### 개념 및 필요성
맥 시스템 프록시나 브라우저 프록시를 물리면, 우리가 감시하려는 AI 서비스뿐만 아니라 **유튜브 비디오 스트리밍(`googlevideo.com`), 노션(`notion.com`), 깃허브, 애플 백그라운드 통신** 등 수많은 무관한 트래픽이 프록시로 쏟아집니다.

만약 모든 트래픽의 바디(Body)를 디스크에 저장(Dump)하면, 몇 분 만에 용량이 수십 기가바이트(GB)로 불어나 프록시가 마비됩니다.

따라서 `TrafficAnalyzer::analyzeRequest` 함수 내부에 **"우리가 관심 있는 AI 도메인 트래픽만 걸러내는 거름망"**을 두는데, 이것이 바로 **호스트 필터 목록**입니다.

### 코드 구조 (`TrafficAnalyzer.cpp`)
```cpp
if ((method == "POST" || method == "PUT" || method == "PATCH") && !body.empty() && 
   (host.find("claude") != std::string::npos || 
    host.find("chatgpt") != std::string::npos || 
    host.find("gemini") != std::string::npos || 
    host.find("aistudio") != std::string::npos || 
    host.find("google") != std::string::npos ||
    host.find("googleapis") != std::string::npos ||
    host.find("openai") != std::string::npos ||         // <--- [추가] OpenAI API/앱 호스트
    host.find("oaiusercontent") != std::string::npos)) { // <--- [추가] OpenAI 스토리지 호스트
    
    // 이 조건에 맞는 트래픽만 captured_files/raw_dumps/*.txt 파일로 디스크에 원본 저장!
}
```

> **💡 왜 아까 ChatGPT 앱 업로드가 덤프되지 않았었나요?**  
> ChatGPT 데스크톱 앱은 `chatgpt.com` 외에도 `api.openai.com`이나 `ios.chat.openai.com`, `oaiusercontent.com`으로 트래픽을 쏩니다. 기존 필터에는 `chatgpt`만 포함되어 있고 `openai`가 빠져 있어서, 통신은 정상 중계되었으나 덤프 파일(`raw_dumps`)로 남지 않았던 것입니다.

---

## 3. 파서 라우팅 및 파서 우회 (Parser Routing & Parser Bypass)란?

### 개념 및 역할
트래픽이 **호스트 필터**를 통과했다고 해서 무조건 파일이 추출되는 것은 아닙니다.  
요청 내용이 단순 텍스트 프롬프트인지, 이미지/문서 파일 업로드인지 **구분하여 적절한 파일 추출기(Parser)로 전달하는 과정**을 **파서 라우팅(Parser Routing)**이라고 합니다.

### 라우팅 파이프라인 단계 (`routeToParser`)

1. **엔드포인트 특화 라우팅:**  
   요청 URL이 `/backend-api/files` 나 `/upload` 처럼 특정 서비스의 전용 업로드 엔드포인트인 경우 전용 파서(`parseChatGPTUpload`)로 먼저 분기합니다.
2. **표준 멀티파트 라우팅:**  
   `Content-Type` 헤더에 `multipart/form-data; boundary=...`가 포함되어 있으면 표준 멀티파트 파일 파서(`parseStandardMultipart`)로 연결합니다.

```cpp
void TrafficAnalyzer::routeToParser(const std::string& host, const std::string& url, 
                                     const std::string& contentType, const std::string& headers, 
                                     const std::string& body) {
    // 1. ChatGPT/OpenAI 업로드 엔드포인트 감지 시
    if ((host.find("chatgpt.com") != std::string::npos || host.find("openai.com") != std::string::npos) &&
        (url.find("/files") != std::string::npos || url.find("/upload") != std::string::npos)) {
        parseChatGPTUpload(body, contentType);
        return;
    }
    
    // 2. 표준 multipart/form-data 형식 감지 시
    if (contentType.find("multipart/form-data") != std::string::npos) {
        parseStandardMultipart(body, boundary);
    }
}
```

### 💡 파서 우회(Bypass) 문제란?
이전에 ChatGPT 전용 엔드포인트를 감지했을 때 `parseChatGPTUpload` 함수를 호출하도록 구현했었으나, 그 내부 코드가:
```cpp
void TrafficAnalyzer::parseChatGPTUpload(...) {
    Logger::info("[Parser] ChatGPT 파일 파싱은 아직 미구현입니다.");
}
```
와 같이 스텁(Stub, 빈 껍데기) 상태로 남아있었습니다.  
이로 인해 ChatGPT 파일 업로드 요청이 들어왔을 때, `return;`으로 바로 끝나버려 아래에 있는 **`parseStandardMultipart` (실제 파일 추출 및 디스크 저장 로직)까지 도달하지 못하고 우회/스킵되는 문제**가 발생했던 것입니다.

### 🛠️ 수정한 해결책
`parseChatGPTUpload` 내부에서도 `Content-Type`이 `multipart/form-data`인 경우 바로 `parseStandardMultipart`를 호출하도록 연결하여, ChatGPT 앱/웹에서 보낸 파일이 `captured_files/` 폴더로 정상 추출되어 저장되도록 완성했습니다.

---

## 4. 요약 정리

| 구성 요소 | 역할 및 기능 | 발생했던 문제 & 해결 |
|:---:|---|---|
| **TLS MITM** | 가짜 CA 인증서로 HTTPS 암호화 스트림 해제 | 앱의 Certificate Pinning 여부에 따라 통신 통과/차단 결정 |
| **TrafficAnalyzer** | 해제된 HTTP 요청의 헤더/바디 분석 총괄 | `POST/PUT/PATCH` 요청의 [Observe] 로그 출력 |
| **호스트 필터** | 지정된 AI 서비스 도메인 트래픽만 덤프 | `openai`, `oaiusercontent` 도메인 추가로 덤프 수집 누락 해결 |
| **파서 라우팅** | `multipart` 또는 전용 파서로 데이터 분기 | 미구현 스텁을 표준 멀티파트 파서로 연동하여 파일 저장 완결 |
