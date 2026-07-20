# proxy_ToInfinity — 빌드/테스트 진행상황 & 다음 할 일 (2026-07-20)

> Infinity 버전(모듈화 리팩터 + 파일 추출/해시/매직넘버)을 **처음으로 실제 빌드·실행 검증**한 기록.

## 상태 한 줄
**빌드 OK + HTTP/1.1 및 HTTP/2 경로 실동작 검증 완료 (업로드 탐지·Content-Encoding 해제 포함).**
(h2는 페이지 로드 + 파일 업로드 탐지까지 검증됨(2026-07-21). CMake 정식 빌드 동작. 남은 것은 "다음 할 일" 참조)

## 빌드 방법 (검증됨)
- 의존: vcpkg `openssl` + `nghttp2`(x64-windows), MSVC(VS2022 vcvars64). CMake 대신 **cl.exe 직접**로 검증.
```
call "...\VC\Auxiliary\Build\vcvars64.bat"
cd proxy_ToInfinity
cl /nologo /EHsc /std:c++17 /utf-8 /I src /I "C:\vcpkg\installed\x64-windows\include" ^
   src/main.cpp src/Core/Logger.cpp src/Core/ProxyServer.cpp src/Crypto/TlsManager.cpp ^
   src/Protocol/Http1Engine.cpp src/Protocol/Http2Engine.cpp src/Inspector/TrafficAnalyzer.cpp ^
   /Fe:proxy_ToInfinity.exe ^
   /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib" libssl.lib libcrypto.lib nghttp2.lib ws2_32.lib crypt32.lib
```
- 실행 준비: exe 옆에 `rootCA.crt`/`rootCA.key` + DLL 4개(`libssl-3-x64.dll`,`libcrypto-3-x64.dll`,`legacy.dll`,`nghttp2.dll`).
- 참고: `CMakeLists.txt`의 nghttp2 링크는 vcpkg에서 `unofficial::nghttp2::nghttp2` 타깃일 수 있어 손봐야 할 수 있음(cl.exe로는 우회함).

## 이번에 고친 진짜 버그 2개
1. **`src/Core/Logger.h`** — `enum { … ERROR }`가 Windows `ERROR` 매크로(wingdi)와 충돌 → **빌드 자체 실패.** enum 앞에 `#undef ERROR/DEBUG` 추가.
2. **`src/Protocol/Http1Engine.cpp`** — 핸드셰이크 순서가 뒤집혀 **업스트림 ALPN 불일치**(서버 h2 ↔ 우리 1.1 텍스트) → 응답이 안 옴. plan_A/B 순서로 복구: **클라 handshake 먼저 → ALPN 확인 → 업스트림엔 같은 프로토콜만 광고.**

## 검증된 동작 (실측)
- HTTPS MITM 복호화: `GET https://example.com → 200`.
- 파일 업로드 식별 + **바이트 정확 추출**: `rootCA.crt`(1240B) 업로드 → `captured_files/rootCA.crt`가 원본과 `cmp` **완전 일치**.
- W9 매직넘버 검증 / W8 해시 / 디스크 저장 전부 동작.

## "버그 아님"으로 판명 (환경 요인)
- **6192B + 매직 불일치** = Fasoo **DRM이 `.pdf`를 암호화**(`DRMONE … Fasoo DRM` 암호문). 프록시는 실제 전송 바이트를 정확히 잡은 것 → **DRM 관측 결과가 우연히 재현됨**(보호 파일은 본문 안 보이고 메타데이터만).
- **503** = httpbin.org가 그 시점 다운(직접 붙어도 000). 프록시는 오히려 닿아서 relay 성공.

## DRM 대비 실측 — 평문 vs 보호 파일 (2026-07-20) ★핵심 발견 근거

같은 추출 파이프라인으로 두 종류 파일을 업로드해 비교. **프록시가 무엇을 얻고 무엇을 못 얻는지가 DRM 여부로 갈린다**는 것을 실측으로 확인.

| 파일 | 위치 | 네트워크로 나간 내용 | 프록시가 본 것 | 추출 결과 |
|---|---|---|---|---|
| `.pdf` (DRM 보호) | 일반 폴더 | `DRMONE … Fasoo DRM` **암호문 6192B** | 메타데이터만(파일명·크기) | 본문=암호문 → 매직넘버 **불일치** |
| `이것은 새로운 파일 이다.docx` (평문) | `C:\Exception\` (DRM 예외) | `PK\x03\x04` **평문 ZIP 13699B** | **본문까지 전부** | 원본과 **바이트 완전 일치**(`cmp` IDENTICAL) |

- 평문 파일: 13699B 전체 추출 → 매직넘버 통과 → `captured_files/`에 **한글 파일명 그대로 정상 저장** → 원본과 완전 일치.
- **의미(DLP 앵글):** 보호 안 된 **평문** 파일이 AI 서비스로 나가면 프록시가 **내용까지 식별·획득** 가능. DRM 보호 파일은 **메타데이터만**(본문은 Fasoo 암호문이라 못 봄). → 프록시의 실질 값어치가 여기서 갈린다. (발표/보고서용 대비표로 그대로 사용 가능)
- **예외 폴더 주의:** `C:\Exception\`는 **거기서 새로 만든 파일**만 평문(README §7). 평문 테스트는 이 폴더에서 생성/저장한 파일로 할 것. (일반 폴더에서 만든 `.pdf`는 DRM에 암호화됨 → 6192B 사례)
- **사소(개선 후보):** 콘솔 로그엔 한글 파일명이 `�̰���...`로 깨져 보임(콘솔 코드페이지 표시 문제일 뿐 — **저장 파일명·내용은 정상**). `SetConsoleOutputCP(CP_UTF8)`로 개선 가능.

## 다음 할 일

> **진행 갱신 2026-07-21:** 아래 대부분 완료(✅). 남은 것(⬜)만 이어가면 됨.

1. **h2 경로 — ✅ 완료.**
   - 중계·복호화(2026-07-20): 헤드리스 크롬으로 example.com + 구글 서비스들이 `H2Bridge`로 h2 정상 로드.
   - **파일 업로드 탐지(2026-07-21):** 크롬이 h2로 fetch-POST한 multipart를 `Http2Engine`(`cb_on_data_chunk`→`analyzeRequest`)가 잡아 `h2test.pdf` 추출·매직넘버 일치·디스크 저장 확인. Plan B RST_STREAM 픽스(`MAKE_NV`) 유효.
2. **코드 리뷰 개선점:**
   - ✅ `std::stoll/stoi` → 안전 파서(`parseLL`) 교체 (비정상 입력에 예외로 스레드 죽던 것)
   - ✅ h1 `analyzeRequest`에 host 대신 **요청 경로** 전달 (ChatGPT 지문 라우팅 정상화)
   - ✅ 응답 body 캡처 **256KB 상한**(`forwardUntilClose`)
   - ✅ **저장 파일명 경로탈출 방어(2026-07-21)** — `sanitizeFilename`(basename만 사용, `../`·드라이브(`:`)·제어문자 제거, 유니코드 보존). `../../pwned.txt`→`pwned.txt`로 안전화되어 `captured_files/` 밖으로 안 새는 것 검증.
   - ⬜ **매직넘버 커버리지 확대**(docx=ZIP `PK`, zip, gif 등)
3. **Content-Encoding 실해제** — ✅ **h1 완료**(zlib gzip/deflate + brotli; en.wikipedia gzip 51485→256057B 검증). ⬜ **h2는 아직 회피(strip)** — 실해제하려면 응답 body 별도 캡처 필요. 상세: `phase5-vs-code-tracking.md`.
4. ⬜ 실제 AI 서비스(claude.ai/ChatGPT) 업로드 지문 캡처 → 서비스별 파서(Phase 6). `parseChatGPTUpload`는 현재 스텁.

## 관련
- 설계/의도: `phase5-walkthrough.md`, `../../docs/ToInfinity/phase5-implementation-plan.md`
- 계획↔코드 차이 추적: `phase5-vs-code-tracking.md`
- CMake 빌드: `cmake-guide.md`
- 프로토콜 개념: `../../proxy_beyond_docs/protocol-handling-6-9.md`
- h2 버그 기록: `../../docs/troubleshooting/h2-rst-stream-bug.md`
