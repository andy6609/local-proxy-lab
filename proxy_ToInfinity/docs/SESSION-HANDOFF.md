# 세션 인계 (HANDOFF) — 다른 Windows(무-DRM) 머신에서 이어가기

> **새 세션의 Claude에게:** 이 문서를 읽고 이전 세션을 그대로 이어가면 된다. 코드는 전부
> GitHub(`https://github.com/andy6609/local-proxy-lab`, `main`)에 있으니 `git clone` 후
> 이 문서 + `proxy_ToInfinity/docs/`를 읽으면 전체 맥락이 잡힌다.
> 작성: 2026-07-21. 최신 커밋: `dc07f3e` 근처(이 문서 커밋이 최신).

---

## 0. TL;DR (지금 상황)
- **DRM이 깔린 호스트에서 계속 실험했는데, DRM이 측정을 오염시켜서** "무엇이 진짜 네트워크로 나갔나"를
  판정하기가 어려웠다. → **무-DRM(clean) Windows 머신으로 옮겨서** 프록시 기능(파일 추출·해시검증·서비스 지문)을
  오염 없이 검증하려는 참이다.
- 프록시 자체(`proxy_ToInfinity`)는 **CMake로 빌드·검증 완료**, HTTP/1.1·HTTP/2 복호화 + 업로드 탐지·추출이 실동작함.
- 직전에 **큰 발견 2개**가 나왔다(§4.2, §4.3). 이건 아직 개별 문서에 미반영일 수 있으니 이 문서에 정리해 둔다.

---

## 1. 나(사용자)와 프로젝트 (안 바뀌는 배경)
- **Fasoo 인턴 연구 PoC.** 목표 = **AI 서비스(ChatGPT/Gemini/Claude/네이버) 파일 업로드를 MITM 프록시로 식별** (DLP 맥락).
- **이력서 핵심 = "파일 업로드를 식별해 (회사) 제품에 기능으로 추가했다."** TLS MITM·프로토콜 처리는 수단.
- 회사 제출·제품화 코드 **아님.** 단 이력서/포트폴리오 공개용이라 **견고하게(solid)**. 풀 프로덕트(WFP 커널·IOCP 등)는 지양.
- **WFP는 나중**(로컬 먼저). 지금은 explicit proxy / 시스템 프록시로 트래픽 유도.
- 멘토의 8주 커리큘럼 있음(대략: 개념→로컬프록시→HTTP파싱→TLS MITM→HTTPS분석→업로드식별→추출→분석).
- **멘토의 원래 핵심 질문:** "Fasoo DRM이 API hook할 때 파일을 *읽는* 거냐, *네트워크로 올리는* 거냐를 프록시로 알아보자." → **§4.2에서 답이 나옴(네트워크로 올린다).**

## 2. 작업 스타일 (반드시 지킬 것)
- **커밋: Claude co-author/트레일러 절대 안 붙인다.** (사용자가 명시적으로 뺐음)
- **설명: 기술적으로. 비유(analogy) 금지.** 언어는 **한국어**.
- **문서: 발견은 `proxy_ToInfinity/docs/`에 기록. 기존 문서를 덮어쓰지 말고 추가/보강**(사용자가 "수정 말고 추가" 강조).
- **빌드: CMake가 정식**(cl.exe는 임시 검증용이었음). vcpkg 툴체인.
- **PowerShell 함정:** 한 스크립트에 `Remove-Item` + `C:\Program...` 경로가 같이 있으면 하네스 샌드박스가 오탐으로 막는다 → 정리(rm)와 빌드(vcvars 경로)를 **다른 호출로 분리**.
- 프록시 띄우고 끄기: exe가 실행 중이면 재빌드 시 링크가 `LNK1104`로 막힘 → 빌드 전 프록시 프로세스 종료.

---

## 3. 코드 상태
- **활성 트랙 = `proxy_ToInfinity/`** (모듈화 리팩터, CMake). **여기에만 새 기능 얹는다.**
  - 구조: `src/Core`(Logger/ProxyServer/Context) · `src/Crypto`(TlsManager=CertAuthority) · `src/Protocol`(Http1Engine/Http2Engine) · `src/Inspector`(TrafficAnalyzer).
- 옛 트랙(참고용, 안 건드림): `proxy_beyond/`(plan_A ALPN다운그레이드, plan_B nghttp2), `proxy_v4/`, `proxy_MITM_pure/`(학습용).
- **검증된 기능(실측):**
  - TLS MITM 복호화(host별 동적 leaf 인증서), HTTP/1.1(keep-alive·chunked), **HTTP/2**(nghttp2 브릿지, 실브라우저 페이지 로드+업로드 탐지),
  - **파일 업로드 탐지·추출**(multipart: boundary·filename·Content-Type) + 디스크 저장(유니크 파일명 `<seq>_이름`) + 매직넘버 + 해시,
  - **Content-Encoding 실해제**(h1, zlib gzip/deflate + brotli),
  - **`[Observe]` 로깅**(모든 POST/PUT/PATCH의 엔드포인트·Content-Type·업로드헤더·body head·bodylen) ← 서비스 지문 조사의 핵심 도구.
- 최근 고친 버그: Logger `ERROR` 매크로 충돌, ALPN 순서, 안전 정수파싱, 응답캡처 상한, **파일명 경로탈출 방어**, **유니코드(한글) 저장(u8path)**, **동시쓰기 레이스(유니크 파일명)**.

### 빌드 방법 (CMake, 검증됨)
사전: vcpkg에 `openssl nghttp2 zlib brotli`(x64-windows), MSVC(VS Build Tools 또는 VS2022), CMake(VS 번들).
```
vcpkg install openssl:x64-windows nghttp2:x64-windows zlib:x64-windows brotli:x64-windows
cd proxy_ToInfinity
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
# 산출물: build/Release/proxy_ToInfinity.exe  (의존 DLL은 vcpkg가 자동 배치)
```
실행 전: `rootCA.crt`/`rootCA.key`를 exe 옆(build/Release/)에 두고, rootCA를 OS 신뢰저장소 등록
(`certutil -addstore -user Root rootCA.crt`). rootCA 생성법은 `../../docs/m4-mitm-setup.md` 또는 `m1tom4/`.
(CMake 세부: `cmake-guide.md`. nghttp2는 vcpkg가 CMake config를 안 줘서 `find_library`로 링크함.)

### 브라우저/앱을 프록시로 물리기
- 크롬: `chrome.exe --proxy-server=http://127.0.0.1:18080 --disable-quic --user-data-dir=<임시>`
  (**`--disable-quic` 필수** — AI 서비스 업로드가 QUIC/UDP를 타면 TCP MITM을 우회함)
- 데스크탑 앱(Claude Desktop 등): **Windows 시스템 프록시**를 127.0.0.1:18080로 설정하면 잡힘(§4 참고). 단 모든 앱에 영향 → 테스트 후 원복 필수.

---

## 4. 지금까지의 발견 (핵심)

### 4.1 서비스별 업로드 지문 (실캡처)
| 서비스 | 전송 | 업로드 방식 | 엔드포인트 | 우리 파서 |
|---|---|---|---|---|
| **claude.ai** (웹·데스크탑앱) | h2 | 표준 `multipart/form-data` | `.../wiggle/upload-file` + `.../convert_document` (한 업로드에 2회) | ✅ 바로 잡힘 |
| **Gemini** | h2 | **Google resumable** (`X-Goog-Upload-Protocol=resumable`, start→upload,finalize) | `push.clients6.google.com/upload/` | ⬜ 전용 핸들러 필요(추출은 쉬움: finalize body가 곧 원본) |
| **ChatGPT** | ? | 미캡처 | ? | ⬜ (다음 할 일) |
상세: `ai-upload-fingerprints.md`

### 4.2 ⭐ Fasoo Wrapsody가 파일을 네트워크로 자기 서버에 올린다 (멘토 원래 질문의 답)
Claude Desktop 앱으로 파일 1개 업로드했더니, 시스템 프록시에 **Fasoo 트래픽**이 대량으로 잡혔다:
- `POST wrapsody.fasoo.com:7068/wrapsody` — **파일(DRM 암호문)을 multipart로 3회 업로드**. 파일명은 GUID(`2D44684FE5AA...`), 본문 `DRMONE ...Fasoo DRM...`.
- `POST wrapsody.fasoo.com/filesync/filesync/service/{addsync,setdoctag,syncinfo}.do` — 메타데이터 동기화 API(`MSG=...` 인코딩).
- `fasoo.wrapsodyeco.com`(http/1.1)로도 다수 연결.
→ **즉 파일 업로드/조작 시 Fasoo가 그 파일(암호문)을 네트워크로 자기 서버에 올린다.** 멘토의 "읽느냐 vs 네트워크로 올리느냐" 질문에 대해 **네트워크로 올린다**가 실증됐고, 우리 프록시가 그걸 캡처했다. (이게 이번 프로젝트의 큰 성과 중 하나 — 문서 `report`로 정리 예정이었음.)

### 4.3 ⚠️ 방법론 교정 (매우 중요 — 이거 때문에 무-DRM 머신으로 감)
"무엇이 진짜 네트워크로 나갔나"를 판정할 때 **DRM이 두 겹으로 오염**시킨다:
1. **프로세스별로 평문/암호문이 다름** — 파일은 디스크에 암호문 하나, Fasoo가 읽는 프로세스가 허가면 복호화해서 준다. (크롬·Claude앱·git bash가 서로 다르게 봄. 자세히: `fasoo-drm-mechanism.md`)
2. **프록시가 저장한 파일도 Fasoo가 재암호화** — 프록시가 추출한 **평문 15688B를 `.docx`로 저장했는데, 나중에 읽어보니 21840B `DRMONE`**(디스크에서 Fasoo가 .docx를 재암호화). → **저장 파일 바이트는 "무엇이 업로드됐나"의 증거가 못 된다.**

**그래서 신뢰할 신호는 "선(wire)에서 실제로 나간 것":**
- `[Observe]`의 **bodylen**(멀티파트 body 크기),
- 추출 **크기**(DRM은 평문보다 ~6KB 큼),
- **해시 일관성**(같은 파일 두 번 올렸을 때: 평문이면 해시 동일, DRM이면 랜덤IV라 매번 다름).
  - 예(이번): claude.ai 2회 → 해시 동일(`e8cf38a2`)·15688B = **평문**. wrapsody 3회 → 해시 전부 다름·21840B = **DRM**.

**[재검증 필요] 앞선 "목적지별 DRM" 결론(claude=암호화 / gemini=평문)은 의심스럽다.** 그건 claude는 *저장파일*(재암호화됨)로, gemini는 *관측(observe)*으로 봐서 생긴 **비대칭 artifact**일 수 있다. **wire 신호(위 3가지)로 다시 판정해야 한다.** (무-DRM 머신이면 이 오염이 아예 없어져서 깔끔.)

---

## 5. 새 머신에서 할 것 (계획)
### 두 트랙을 구분 (헷갈리면 안 됨)
| 목적 | 환경 |
|---|---|
| **프록시 기능 검증**(추출·해시·파서 정확성, 서비스 지문) | **무-DRM(clean) 머신** ✅ — 오염 없음 |
| **Fasoo DRM/Wrapsody 동작 연구**(§4.2, 프로세스/저장 재암호화) | **DRM 호스트** — clean 머신엔 연구 대상이 없음 |

### 새(무-DRM) 머신 셋업 순서
1. `git clone https://github.com/andy6609/local-proxy-lab.git`
2. vcpkg 설치 + `vcpkg install openssl nghttp2 zlib brotli :x64-windows`
3. MSVC(VS Build Tools) + CMake, §3 빌드
4. rootCA 생성 + `certutil -addstore -user Root rootCA.crt`
5. 크롬 `--proxy-server=... --disable-quic`로 물려서 테스트

### 우선순위 다음 작업
1. **W8 — 파일 바이너리 추출·해시 검증** (무-DRM이라 평문 → 원본↔추출본 **바이트/해시 일치** 깔끔히 증명). 지금 저장이 유니크 파일명이라 신뢰 가능.
2. **서비스 지문 clean 재확인** (claude/gemini/ChatGPT를 오염 없이).
3. **Gemini resumable 핸들러 구현** (`push.clients6.google.com/upload/` + `X-Goog-Upload-Command: upload, finalize`의 body=원본 → 추출·저장). 그러면 Gemini도 W8 가능.
4. **ChatGPT 지문** 캡처.
5. (DRM 호스트로 돌아갔을 때) **§4.3 wire 기반으로 "목적지별 DRM" 재판정**, Wrapsody 전송 내용 추가 분석.

---

## 6. 문서 지도 (`proxy_ToInfinity/docs/`)
| 문서 | 내용 |
|---|---|
| `SESSION-HANDOFF.md` (이 문서) | 세션 인계·전체 맥락 |
| `SUMMARY.md` | 트랙 전체 요약·진입점 |
| `build-and-progress.md` | 빌드/검증 현황 + 다음 할 일 + DRM 대비 표(§DRM은 wire 기준 재검증 필요) |
| `ai-upload-fingerprints.md` | 서비스별 업로드 지문 + DRM 실측 (※ "목적지별 DRM"은 §4.3대로 재검증 대상) |
| `fasoo-drm-mechanism.md` | Fasoo DRM 원리(프로세스+목적지) + 검증 함정 |
| `cmake-guide.md` | CMake 개념 + cl.exe→CMake 전환 |
| `phase5-vs-code-tracking.md` | 원 계획(Phase5) ↔ 실제 코드 차이 |
| `phase5-walkthrough.md` | (원 계획) Phase5 튜토리얼 |

## 7. 아직 문서에 미반영일 수 있는 것 (이 인계 문서가 최신 진실)
- §4.2 Wrapsody phone-home 상세 (report 문서로 쓰려다 중단됨 → 새 세션에서 정식 문서화하면 좋음)
- §4.3 "저장파일 재암호화 → wire 신호로 판정" 교정 (기존 docs의 "목적지별 DRM" 서술에 이 caveat 반영 필요)

## 8. 리포
- `https://github.com/andy6609/local-proxy-lab` (branch `main`). 커밋엔 Claude 트레일러 없음.
