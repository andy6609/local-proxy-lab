# ChatGPT Classic (macOS 데스크톱 앱) 파일 업로드 캡처 실패 분석

> **분석 일시:** 2026-07-22  
> **대상:** ChatGPT Classic v1.2026.184 (macOS, Swift 네이티브 앱)  
> **결론:** macOS 환경에서 일반적인 프록시 방식으로는 파일 업로드 트래픽 캡처 불가

---

## 1. 시도한 방법과 결과

### 시도 A: 환경변수 프록시 주입
```bash
http_proxy="http://127.0.0.1:18080" https_proxy="http://127.0.0.1:18080" \
"/Applications/ChatGPT Classic.app/Contents/MacOS/ChatGPT Classic" &
```
**결과:** ❌ 실패  
- 앱은 정상적으로 실행되고 터미널에 `[Statsig]` 내부 로그가 출력됨
- 그러나 프록시 서버(`proxy_ToInfinity`)에는 파일 업로드 트래픽이 단 1건도 수신되지 않음
- `[Statsig]` 로그는 프록시를 거쳐서 출력된 것이 아니라 앱 자체의 `stderr` 콘솔 출력

### 시도 B: macOS 시스템 네트워크 프록시 설정
```
시스템 설정 → 네트워크 → Wi-Fi → 세부 정보 → 프록시
→ 웹 프록시(HTTP): 127.0.0.1 / 18080
→ 보안 웹 프록시(HTTPS): 127.0.0.1 / 18080
```
**결과:** ❌ 실패  
- 시스템 프록시를 켜면 ChatGPT 앱 자체가 접속 불가 상태에 빠짐
- 프록시의 MITM 가짜 인증서(Root CA)를 앱이 거부하여 TLS 핸드셰이크 실패
- 프록시 로그에 `SSL_accept failed: unexpected eof while reading` 에러 출력

---

## 2. 근본 원인: Swift 네이티브 앱 vs Electron 앱

### 앱 프레임워크 확인
```
/Applications/ChatGPT Classic.app/Contents/Frameworks/
├── ChatGPT.framework        ← Swift 네이티브
├── LiveKitWebRTC.framework  ← WebRTC (음성통화용)
├── Lottie.framework         ← 애니메이션
├── Sparkle.framework        ← 자동 업데이트
└── libswiftCompatibilitySpan.dylib
```
Electron 프레임워크(`Electron Framework.framework`) 없음 → **순수 Swift/AppKit 네이티브 앱**

### Claude 앱과의 비교

| 항목 | Claude Desktop | ChatGPT Classic |
|------|---------------|-----------------|
| **프레임워크** | Electron (Node.js/Chromium) | Swift (네이티브 macOS) |
| **네트워크 스택** | Node.js `http` 모듈 | Apple `URLSession` |
| **`http_proxy` 환경변수** | ✅ 인식함 | ❌ 무시함 |
| **시스템 프록시 설정** | ✅ 따름 | ✅ 따르지만 아래 문제 발생 |
| **MITM 가짜 CA 인증서** | ✅ 시스템 키체인 신뢰 수용 | ❌ 거부 (Certificate Pinning 또는 ATS) |
| **프록시 캡처 가능 여부** | ✅ 가능 | ❌ 불가 |

### 왜 Claude는 되고 ChatGPT는 안 되는가?

1. **환경변수 프록시:**  
   Claude는 Electron(Node.js) 기반이라 `http_proxy` 환경변수를 자동으로 읽습니다. ChatGPT Classic은 Swift의 `URLSession`을 사용하는데, 이 API는 환경변수를 무시하고 macOS System Configuration Framework에서만 프록시 정보를 가져옵니다.

2. **시스템 프록시 + TLS:**  
   시스템 프록시를 켜면 ChatGPT 앱도 프록시로 트래픽을 보내긴 합니다. 하지만 프록시가 MITM을 위해 제시하는 가짜 인증서를 앱이 거부합니다.  
   - Claude(Electron)는 macOS 키체인에 등록된 Root CA를 신뢰하므로 가짜 인증서를 수용
   - ChatGPT(Swift)는 Apple의 **App Transport Security(ATS)** 정책 또는 자체 **Certificate Pinning**에 의해 키체인에 등록된 사용자 CA를 무시하고 연결을 즉시 끊어버림

---

## 3. 프록시 로그에서 확인된 증거

### 환경변수 방식 (시도 A)
프록시 터미널에 ChatGPT 관련 `[Observe]` 로그 없음. 트래픽 자체가 프록시에 도달하지 않음.

### 시스템 프록시 방식 (시도 B)
```
[ERROR] Client SSL_accept failed for [ios.chat.openai.com] SSL_get_error=1 
        ERR=error:0A000126:SSL routines::unexpected eof while reading
[ERROR]   -> SSL_ERROR_SSL detail: verify_result=0 
        lib=SSL routines reason=unexpected eof while reading
```
- TLS 핸드셰이크 2단계에서 프록시가 가짜 인증서를 보냄
- 앱이 인증서를 검증한 뒤 "가짜"로 판단하고 TCP 연결을 즉시 종료(EOF)
- 프록시는 HTTP 헤더나 바디를 1바이트도 읽지 못함

### 참고: 일부 텔레메트리 트래픽은 잡혔음
시스템 프록시가 켜져 있던 시점에 `chatgpt.com/ces/v1/b` (Segment Analytics 텔레메트리) 트래픽은 프록시에 정상 수신됨. 이는 텔레메트리 모듈이 메인 API와 다른 네트워크 설정(Certificate Pinning 미적용)을 사용하기 때문으로 추정.

---

## 4. 결론 및 향후 대안

macOS 환경에서 ChatGPT Classic 앱의 파일 업로드 트래픽을 캡처하려면 일반적인 HTTP/HTTPS 프록시 방식으로는 불가능하며, 아래와 같은 고급 기법이 필요합니다:

| 대안 | 설명 | 난이도 |
|------|------|--------|
| **1. 크롬 브라우저로 우회** | `chatgpt.com` 웹 버전을 프록시가 물린 크롬에서 사용 | 🟢 쉬움 |
| **2. SSL Kill Switch (탈옥/SIP 해제)** | macOS SIP를 끄고 DYLD_INSERT로 SSL Pinning 우회 라이브러리 주입 | 🔴 매우 어려움 |
| **3. 패킷 캡처 (tcpdump/Wireshark)** | TLS 암호화된 상태로 패킷 캡처 (복호화 불가, 메타데이터만 확인) | 🟡 보통 |
| **4. Frida/LLDB 동적 계측** | 런타임에 URLSession 호출을 후킹하여 평문 데이터 추출 | 🔴 어려움 |

> **현실적 권장:** ChatGPT 파일 업로드 지문 분석은 **크롬 브라우저(프록시 적용) + chatgpt.com 웹 버전**으로 진행하는 것이 가장 확실하고 깔끔한 방법입니다.
