# 🚀 4대 주요 AI 서비스 파일 업로드 아키텍처 및 보안 특성 종합 분석

> **작성 일시:** 2026-07-22  
> **목적:** 사내 보안(DLP) 시스템 및 네트워크 프록시(MITM) 환경에서 각 AI 서비스(Claude, Gemini, ChatGPT, Antigravity)의 파일 업로드 트래픽이 어떻게 동작하는지 아키텍처 관점에서 심층 분석하여 사내 발표 및 기술 검토용으로 활용.

---

## 1. 서론 (Introduction)

최근 기업 내 AI 서비스 도입이 가속화되면서, 임직원들이 사내 기밀 문서나 소스 코드를 AI 플랫폼에 무단으로 업로드하는 것을 방지하는 데이터 유출 방지(DLP) 솔루션의 중요성이 대두되고 있습니다. 

본 문서는 커스텀 HTTP/2 MITM 프록시(`proxy_ToInfinity`)를 직접 구축하여 **Claude, Gemini, ChatGPT, Antigravity** 4개 주요 AI 서비스의 실제 파일 업로드 트래픽(Raw Payload)을 캡처하고 분석한 기술적 결과를 담고 있습니다. 

분석 결과, 각 서비스는 웹 브라우저 기반인지, 데스크톱 앱(Electron vs Native)인지에 따라 네트워크 프로토콜과 보안 방어 메커니즘(Certificate Pinning 등)에서 극명한 차이를 보였습니다.

---

## 2. 서비스별 아키텍처 및 업로드 특성 심층 분석

### 🟢 1. Claude (Anthropic) - "표준의 정석, 가장 투명한 구조"

Claude는 웹 버전과 데스크톱 앱 모두 표준 웹 기술을 가장 정직하게 따르고 있어, 네트워크 레벨의 모니터링과 통제가 가장 용이한 아키텍처를 가집니다.

* **네트워크 스택:** 웹(Chrome/Safari) 및 데스크톱 앱(Electron 기반)
* **업로드 프로토콜:** 표준 **`multipart/form-data`**
* **주요 엔드포인트:** `POST https://claude.ai/api/organizations/{org_id}/wiggle/upload-file`
* **데스크톱 앱 특성:** 
  * Claude의 Mac 데스크톱 앱은 Node.js/Chromium 기반의 **Electron 프레임워크**로 개발되었습니다.
  * 따라서 OS의 시스템 프록시 설정이나 터미널 환경변수(`http_proxy`)를 완벽하게 상속받습니다.
  * 시스템 키체인에 등록된 사내 보안용 가짜 Root CA 인증서를 순순히 신뢰하므로, 앱에서 발생하는 트래픽도 100% 복호화 및 파일 추출이 가능합니다.
* **보안 통제 난이도:** **[최하]** 기존 사내 프록시 장비의 기본 멀티파트 파서만으로도 100% 원본 파일 추출 및 차단이 가능합니다.

---

### 🟡 2. Google Gemini (AI Studio 포함) - "독자적인 인프라 규격"

Gemini는 구글의 거대한 클라우드 인프라(GCP, GCS)를 활용하기 때문에, 일반적인 REST API 표준과는 다른 독자적인 파일 업로드 규격을 사용합니다.

* **네트워크 스택:** 웹 (Web)
* **업로드 프로토콜:** **Google Resumable Upload Protocol (구글 이어올리기 규격)**
* **주요 엔드포인트:** `POST https://push.clients6.google.com/upload/`
* **아키텍처 특성:**
  * 트래픽이 `gemini.google.com`이 아닌 구글의 글로벌 공용 업로드 인프라(`push.clients6.google.com`)로 분산되어 전송됩니다.
  * `multipart/form-data` 바운더리를 사용하지 않고, 1단계에서 메타데이터를 전송(`x-goog-upload-command: start`)한 뒤, 2단계에서 **Raw Binary 데이터만 통째로 전송**(`x-goog-upload-command: upload, finalize`)합니다.
  * 트래픽 헤더에 `x-tenant-id: bard-storage`가 포함되어 있어, 이 파일이 구글 드라이브용인지 제미나이용인지 식별할 수 있습니다.
* **보안 통제 난이도:** **[보통]** 트래픽 복호화는 가능하지만, 구글 전용 헤더(`x-goog-upload-*`)를 파싱하여 메타데이터와 바이너리를 직접 분리해 내는 **맞춤형 파서(Custom Parser)** 개발이 필수적입니다.

---

### 🟠 3. ChatGPT (OpenAI) - "네이티브 앱의 강력한 보안 장벽"

ChatGPT는 웹과 Mac 데스크톱 앱의 내부 아키텍처가 완전히 다릅니다. 특히 Mac 데스크톱 앱은 Apple의 최신 네이티브 기술을 사용하여 사내 보안 장비를 무력화하는 강력한 방어 기제를 보여줍니다.

* **네트워크 스택:** 
  * 웹: React 기반 표준 브라우저 스택
  * 데스크톱 앱: **Swift, AppKit, URLSession 기반 순수 Native macOS 앱**
* **업로드 프로토콜:** `multipart/form-data` 및 Direct-to-Storage (S3/Azure Presigned URL)
* **데스크톱 앱(Native)의 강력한 보안 특성:**
  * **환경변수 무시:** Swift 기반의 `URLSession`은 터미널의 `http_proxy` 환경변수를 원천적으로 무시합니다.
  * **인증서 고정 (Certificate Pinning / ATS):** Mac 시스템 프록시를 강제로 켜서 트래픽을 프록시로 유도하더라도, 앱 내부적으로 사설 Root CA(프록시의 MITM 가짜 인증서)를 철저히 거부합니다.
  * 가짜 인증서를 감지하는 즉시 TLS 핸드셰이크 단계에서 `unexpected eof while reading` 에러를 뱉으며 TCP 연결을 스스로 끊어버립니다. (Statsig, Datadog 텔레메트리 등 일부 예외 존재)
* **보안 통제 난이도:** 
  * **웹:** [보통] S3/Azure Storage 도메인을 프록시 감시 목록에 추가하면 추출 가능.
  * **앱:** **[매우 어려움]** 앱 바이너리 해킹(SSL Kill Switch)이나 MDM 단말 통제 없이는 네트워크 프록시 장비만으로 트래픽 복호화가 원천적으로 불가능합니다.

---

### 🔴 4. Antigravity (Google DeepMind) - "망 분리급 철통 이중 보안"

보안이 극도로 중요한 사내 엔터프라이즈 에이전트/IDE 도구인 Antigravity는 일반적인 프록시 감시망을 아예 처음부터 우회하도록 설계되어 있습니다.

* **네트워크 스택:** gRPC, WebSockets, 커스텀 TCP 소켓
* **아키텍처 특성 (이중 방어 메커니즘):**
  1. **Proxy Bypass (1차 방어):** 메인 통신 모듈이 OS에 설정된 시스템 프록시 정보(HTTP/HTTPS)를 완전히 무시하고, 백엔드 서버와 다이렉트 소켓 통신을 시도합니다.
  2. **Strict Certificate Pinning (2차 방어):** 방화벽(pf/iptables) 수준에서 강제로 프록시로 트래픽을 리다이렉트 시키더라도, 자체 Trust Store를 통해 구글/내부망 공식 인증서가 아니면 즉시 연결을 파기합니다.
* **보안 통제 난이도:** **[최상]** 일반적인 L7 프록시나 웹 게이트웨이(SWG)로는 가로채기가 불가능합니다. 

---

## 3. 기술적 시사점 및 결론 (Technical Takeaways)

AI 서비스 트래픽을 제어하고 파일 유출을 방지하려는 기업 보안팀은 다음과 같은 시사점을 고려해야 합니다.

1. **프레임워크에 따른 통제력 차이 (Electron vs Native):**
   * Claude처럼 웹 기술(Electron)로 만들어진 앱은 기존 프록시 환경에 잘 순응하지만, ChatGPT Mac 앱처럼 **OS Native 언어(Swift, C++)로 만들어진 앱은 자체 보안 정책(ATS, Pinning)을 강력하게 적용**하므로 프록시 장비만으로는 통제가 어렵습니다.
2. **다양해지는 데이터 전송 규격:**
   * 단순히 `multipart/form-data`만 감시해서는 안 됩니다. Gemini의 Google Resumable Protocol이나 ChatGPT의 클라우드 스토리지 직접 송신(Presigned URL) 패턴까지 파싱할 수 있는 **지능형 다중 파서**가 요구됩니다.
3. **네트워크 레벨 통제의 한계 도래:**
   * Antigravity나 ChatGPT 앱처럼 프록시를 자체적으로 회피하거나 인증서를 고정(Pinning)하는 서비스가 늘어남에 따라, 네트워크 단(Proxy)에서의 방어뿐만 아니라 단말기 단(Endpoint/EDR)에서의 통제가 병행되어야 완벽한 보안(DLP)을 달성할 수 있습니다.

---
*본 문서는 `proxy_ToInfinity` 커스텀 프록시 환경에서의 실측 데이터를 바탕으로 작성되었습니다.*
