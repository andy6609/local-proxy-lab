# AI 서비스별 파일 업로드 메커니즘 종합 비교 분석 보고서

> **작성 일시:** 2026-07-22  
> **분석 환경:** macOS (Antigravity Antigravity Agent, Pure Mac Environment)  
> **검증 도구:** 커스텀 HTTP/2 지원 MITM 프록시 (`proxy_ToInfinity`) 및 Raw Payload Dumper

---

## 1. 개요 (Overview)

주요 4대 AI 서비스(Claude, Gemini, ChatGPT, Antigravity)의 웹/데스크톱 앱 환경에서 **파일 업로드 시 일어나는 네트워크 트래픽 구조 및 프로토콜 메커니즘**을 실측 덤프 데이터 및 기술 분석을 통해 종합 비교한 결과입니다.

각 AI 서비스별로 파일 업로드를 처리하는 방식은 **표준 HTML Form**, **구글 전용 클라우드 이어올리기 규격**, **S3/Cloudflare Presigned URL**, **gRPC/커스텀 보안 소켓** 등으로 극명하게 갈립니다.

---

## 2. AI 서비스별 파일 업로드 프로토콜 상세 비교

### 1) Anthropic Claude (웹 & 데스크톱 앱)
* **식별 여부:** ✅ **완벽 식별 및 파싱 검증 완료**
* **업로드 엔드포인트:** `POST https://claude.ai/api/organizations/{org_id}/wiggle/upload-file`
* **프로토콜 및 트래픽 포맷:** **표준 HTTP `multipart/form-data`**
  * `----WebKitFormBoundary...` 바운더리로 둘러싸인 바이너리 폼 데이터.
* **웹(Web) vs 데스크톱 앱(App) 차이점:**
  * **패킷 구조 100% 동일:** 앱과 웹 모두 동일한 REST API 엔드포인트와 멀티파트 바운더리를 사용.
  * **헤더 차이:** 데스크톱 앱은 식별용 커스텀 헤더가 추가됨:
    * `anthropic-client-app: com.anthropic.claudefordesktop`
    * `anthropic-client-platform: desktop_app`
* **보안 및 프록시 가로채기:** 표준 OS 시스템 프록시 및 CA 신뢰를 수용하므로, 일반적인 DLP(데이터 유출 방지) 프록시로 100% 원본 파일 추출 가능.

---

### 2) Google Gemini (웹 & AI Studio)
* **식별 여부:** ✅ **완벽 식별 완료 (구글 독자 규격 포착)**
* **업로드 엔드포인트:** `POST https://push.clients6.google.com/upload/`
* **프로토콜 및 트래픽 포맷:** **Google Resumable Upload Protocol (구글 이어올리기 규격)**
  * `gemini.google.com`이 아닌 구글 글로벌 인프라(`push.clients6.google.com`)로 우회 송신.
  * **1단계 (Handshake):** `x-goog-upload-command: start` 헤더와 함께 메타데이터 송신.
  * **2단계 (Binary Transfer):** `x-goog-upload-command: upload, finalize` 헤더와 함께 raw 바이너리 수송 (멀티파트 바운더리 없음).
  * **테넌트 구분:** `x-tenant-id: bard-storage` 헤더로 제미나이 전용 파일임을 식별.
  * **프롬프트 전송:** 파일 업로드 후 발급받은 토큰을 `POST /_/BardChatUi/data/batchexecute` (URL-encoded `jspb` 배열)에 실어 보냄.

---

### 3) OpenAI ChatGPT (웹 & 데스크톱/iOS 앱)
* **식별 여부:** 🟡 **식별 및 텔레메트리/API 모니터링 완료**
* **업로드 엔드포인트:** `POST https://chatgpt.com/backend-api/files` 또는 Presigned Storage (S3/Azure Blob)
* **프로토콜 및 트래픽 포맷:** **Direct-to-Storage (Presigned URL) 또는 API Upload**
  * 1단계로 파일 메타데이터를 백엔드 API에 보내 업로드용 임시 URL(Presigned URL)을 발급받음.
  * 2단계로 Storage(S3 등)로 직접 바이너리를 쏘거나, `multipart/form-data`로 API 서버에 직접 업로드.
* **앱(Desktop/iOS) 특성:**
  * `ios.chat.openai.com` 및 telemetry 엔드포인트(`ces/v1/telemetry/intake`) 활용.
  * 일부 분석/보안 엔드포인트는 TLS 프록시 재조작 시 `unexpected eof`를 발생시키며 통신 차단.

---

### 4) Google DeepMind Antigravity (전용 앱 & IDE 에전트)
* **식별 여부:** 🔬 **이중 방어 메커니즘 (프록시 우회 + Certificate Pinning) 확인**
* **업로드 엔드포인트:** `antigravity-hub-auto-updater...` 및 gRPC/커스텀 소켓 엔드포인트
* **프로토콜 및 트래픽 포맷:** **gRPC / WebSockets 기반 이중 방어 통신**
* **방어 특징:**
  1. **1차 방어 (Proxy Bypass):** OS 레벨의 HTTP/HTTPS 프록시 설정을 완전히 무시하고 다이렉트 TCP 소켓 연결을 시도함.
  2. **2차 방어 (Strict Certificate Pinning):** 강제로 프록시에 집어넣을 경우, 프록시의 MITM 가짜 Root CA를 감지하자마자 TLS 핸드셰이크 단계에서 TCP 연결을 강제 종료 (`SSL_accept failed: unexpected eof while reading`).

---

## 3. 요약 및 DLP(사내 보안) 관점에서의 시사점

| AI 서비스 | 업로드 방식 | 메타데이터/바이너리 형태 | 프록시 차단/추출 난이도 |
|:---:|:---:|:---:|:---:|
| **Claude** | REST API (`multipart`) | 웹/앱 동일한 멀티파트 바운더리 | 🟢 **쉬움** (표준 파서로 100% 원본 복원 가능) |
| **Gemini** | Google Resumable Protocol | Raw Binary + `x-goog-upload-*` 헤더 | 🟡 **보통** (구글 전용 프로토콜 헤더 파싱 필요) |
| **ChatGPT** | Presigned URL / Multipart | REST API + Storage 직접 송신 | 🟡 **보통** (Storage 도메인 추가 허용 필요) |
| **Antigravity** | gRPC / Custom Socket | 보안 소켓 / 암호화 트래픽 | 🔴 **어려움** (Pinning 해제 패칭 필수) |

---
*본 문서는 `proxy_ToInfinity` 프로젝트의 보안 연구용 덤프 분석 결과를 바탕으로 작성되었습니다.*
