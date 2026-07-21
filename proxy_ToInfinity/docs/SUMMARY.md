# proxy_ToInfinity — 여기까지 요약 (2026-07-21)

> 이 트랙 전체를 한눈에 보는 진입점. 세부는 각 문서로 링크. (기존 문서 대체 아님, 요약 추가)

## 한 줄 상태
**모듈화 프록시(Infinity)를 CMake로 빌드·검증 완료. HTTP/1.1·HTTP/2 복호화 + 파일 업로드 탐지·추출이 실동작하고, 실제 AI 서비스(claude.ai·Gemini) 업로드를 캡처해 서비스별 지문과 Fasoo DRM 동작을 실측함.**

---

## 1. 무엇을 만들었나 (Infinity 프록시)
`namespace proxy` 아래 모듈화: Core(Logger/ProxyServer/Context) · Crypto(TlsManager/CertAuthority) · Protocol(Http1Engine/Http2Engine) · Inspector(TrafficAnalyzer). CMake 빌드(vcpkg: openssl·nghttp2·zlib·brotli).

**실측 검증된 기능:**
- ✅ TLS MITM 복호화 (host별 동적 leaf 인증서)
- ✅ **HTTP/1.1** 파싱·중계 (Keep-Alive·chunked)
- ✅ **HTTP/2** 실제 파싱 (nghttp2 브릿지) — 실브라우저 페이지 로드 + 업로드 탐지 확인
- ✅ **파일 업로드 탐지·추출** (multipart: boundary·filename·Content-Type) + 디스크 저장 + 매직넘버(W9)·해시(W8) + **바이트 정확 추출**(비-DRM 파일로 원본 일치 확인)
- ✅ **Content-Encoding 실해제**(h1, zlib gzip/deflate + brotli)
- ✅ **`[Observe]` 로깅** — 모든 POST/PUT/PATCH의 엔드포인트·Content-Type·업로드헤더·body head (multipart 아닌 업로드까지 관측)

세부: `build-and-progress.md`, 빌드법: `cmake-guide.md`, 계획↔코드 차이: `phase5-vs-code-tracking.md`

---

## 2. ⭐ 핵심 발견 — Fasoo DRM은 "3중 조건"
프록시가 업로드 파일의 **내용**을 볼 수 있느냐는 세 가지에 달렸다(전부 실측):

1. **파일의 DRM 여부** — 보호 문서면 본문이 `DRMONE` 암호문.
2. **읽는 프로세스** — git bash(허가)=평문 / **크롬(비허가)=암호문**. (파일은 디스크에 암호문 하나, DRM이 프로세스별로 복호화)
3. **업로드 목적지(사이트)** — **같은 파일이라도 claude.ai=암호화 / Gemini=평문**. Fasoo 보호에 **사이트 allowlist** 성격, **Gemini는 미커버(사각지대)**.

→ **결론(DLP):** 프록시의 값어치 = **보호 안 되고 새는 것(비-DRM 파일, 미커버 목적지)을 내용까지 잡아내는 것.** DRM 보호분은 메타데이터만.
원리 상세: `fasoo-drm-mechanism.md`

### ⚠️ 검증 함정
"평문인가"를 **git bash(허가 프로세스)로 판단하면 틀림.** 반드시 **프록시 캡처(=크롬이 실제 보낸 바이트)** 로 판정.

---

## 3. 서비스별 업로드 지문 (실캡처)
| 서비스 | 전송 | 업로드 방식 | 엔드포인트 | 목적지 DRM | 우리 파서 |
|---|---|---|---|---|---|
| **claude.ai** | h2 | 표준 `multipart/form-data` | `.../wiggle/upload-file` + `.../convert_document` (한 업로드에 2회) | **암호화됨** | ✅ 바로 잡힘 |
| **Gemini** | h2 | **Google resumable** (`X-Goog-Upload-*`) | `push.clients6.google.com/upload/` (start→upload,finalize) | **평문 통과** | ⬜ 전용 핸들러 필요(추출은 쉬움: finalize body=원본) |

세부·로그: `ai-upload-fingerprints.md`

---

## 4. 이번에 고친/추가한 것 (커밋)
- 빌드: Logger `ERROR` 매크로 충돌, CMake nghttp2 `find_library`+zlib/brotli+`/utf-8`
- 견고성: 안전 파싱(`parseLL`), h1 analyzer에 요청경로 전달, 응답캡처 상한, **파일명 경로탈출 방어**, **유니코드(한글) 저장**(`u8path`), **동시쓰기 레이스**(유니크 파일명)
- 기능: Content-Encoding 실해제(h1), 엔드포인트 URL 로깅, `[Observe]` 로깅

---

## 5. 남은 것 / 다음
- ⬜ **ChatGPT 지문** (세 번째 서비스 — allowlist에 있나? 표준 multipart냐?)
- ⬜ **Gemini resumable 핸들러** — 평문 통과하는 걸 실제 추출·저장 → **W8(해시검증)** 로 직결
- ⬜ **목적지별 DRM 정책** 추가 검증(다른 사이트들), Fasoo 정책 확인
- ⬜ h2 Content-Encoding 실해제, 매직넘버 커버리지(docx=ZIP 등), ChatGPT 전용 파서

---

## 문서 지도
| 문서 | 내용 |
|---|---|
| `SUMMARY.md` (이 문서) | 전체 요약·진입점 |
| `build-and-progress.md` | 빌드/검증 현황 + 다음 할 일 + DRM 대비 표 |
| `ai-upload-fingerprints.md` | 서비스별 업로드 지문 + DRM 실측 |
| `fasoo-drm-mechanism.md` | Fasoo DRM 원리(프로세스+목적지) + 검증 함정 |
| `cmake-guide.md` | CMake가 뭔지 + cl.exe→CMake 전환 |
| `phase5-vs-code-tracking.md` | Phase5 계획 ↔ 실제 코드 차이 추적 |
| `phase5-walkthrough.md` | (원 계획) Phase5 튜토리얼 |
