# proxy_ToInfinity — 빌드/테스트 진행상황 & 다음 할 일 (2026-07-20)

> Infinity 버전(모듈화 리팩터 + 파일 추출/해시/매직넘버)을 **처음으로 실제 빌드·실행 검증**한 기록.

## 상태 한 줄
**빌드 OK + HTTP/1.1 경로 실동작 검증 완료.** (h2 경로는 아직 미검증)

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

## 다음 할 일
1. **h2 경로 검증** — 실브라우저(크롬 `--disable-quic`)로 `Http2Engine`(Plan B 브릿지 이식본) 실동작 확인. (Plan B의 RST_STREAM 픽스 `MAKE_NV`는 반영돼 있으나 미검증)
2. **코드 리뷰 잔여 개선점(유효):**
   - `Http1Engine`의 `std::stoll`/`std::stoi` → **예외 던짐**(detached 스레드에서 uncaught = 프로세스 종료). v4식 안전 파서로 교체.
   - `analyzeRequest`에 h1은 url 대신 **host를 넘김** → ChatGPT 지문 라우팅이 h1에서 안 됨. 요청 경로 전달로 수정.
   - 응답 body **무제한 캡처**(`forwardUntilClose`) → 상한/비활성화.
   - 저장 파일명 경로안전(`../`)·유니코드(한글) 처리, 매직넘버 커버리지 확대(docx=ZIP 등).
3. **Content-Encoding 실해제**(zlib/brotli) — 현재는 Accept-Encoding 제거(회피)만. `proxy_beyond_docs/protocol-handling-6-9.md` §9에 구현법 정리됨.
4. 실제 AI 서비스(claude.ai/ChatGPT) 업로드 지문 캡처 → 서비스별 파서(Phase 6).

## 관련
- 설계/의도: `docs/phase5-walkthrough.md`, `../docs/ToInfinity/phase5-implementation-plan.md`
- 프로토콜 개념: `../proxy_beyond_docs/protocol-handling-6-9.md`
- h2 버그 기록: `../docs/troubleshooting/h2-rst-stream-bug.md`
