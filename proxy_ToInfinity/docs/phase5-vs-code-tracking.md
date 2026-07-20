# Phase 5 계획 ↔ 실제 코드 차이 추적

> Phase 5 계획 문서(`phase5-walkthrough.md`, `../../docs/ToInfinity/phase5-implementation-plan.md`)가
> 말한 것과, **실제 빌드/검증을 거치며 바뀐 코드**가 어디서 갈라지는지 추적한다.
> "계획대로 간 것 / 안 간 것 / 왜"를 한곳에서 볼 수 있게. (최종 갱신 2026-07-21)

## ★ headline: Content-Encoding — "회피(strip)" → "실해제(decode)"

이게 계획과 코드가 가장 크게 갈린 지점이다.

| | Phase 5 문서가 말한 것 | protocol-handling-6-9 §9 | **현재 코드** |
|---|---|---|---|
| 방식 | **Accept-Encoding 제거로 압축 회피** (walkthrough §3, plan §2 "1-B") — "복잡한 zlib 연동 없이" | strip은 "꼼수", **실해제(zlib/brotli)가 정답** | **h1: 실해제로 교체** / h2: 아직 strip |
| 이유 | 당장 간단하게 평문 응답 유도 | 응답 본문을 우리도 읽으려면 결국 해제 필요 | §9 채택, 실제 구현·검증 |

**구체적 코드 상태 (2026-07-21):**
- **HTTP/1.1 경로 = 실해제.**
  - `Http1Engine`: Accept-Encoding **제거 로직 삭제**(이제 그대로 전달 → 서버가 압축).
  - `TrafficAnalyzer::decodeBody`: zlib(gzip/deflate, `windowBits=15+32`) + brotli(`br`) 해제.
  - `analyzeResponse`가 캡처한 응답 body를 해제하고 로그(`[Decode] gzip: 51485B→256057B`). **검증됨**(en.wikipedia.org).
  - 클라이언트로는 **압축 그대로 relay**(브라우저가 해제) — relay 무영향.
- **HTTP/2 경로 = 아직 회피(strip).**
  - `Http2Engine::skipReqHeader`에 `accept-encoding`이 남아 있어 **여전히 제거**한다.
  - 게다가 h2는 응답 body를 `analyzeResponse`에 안 넘김(`"[Body Data Omitted]"`)이라 해제 대상이 없음.
  - → **h2 실해제는 TODO** (H2Stream에 응답 캡처 버퍼 추가 + 실제 Content-Encoding 헤더 전달 필요).

**따라서 갱신 필요 문서:** `phase5-walkthrough.md` §3 "압축 회피"는 **h1에선 더 이상 사실이 아님**(실해제로 대체). h2에서만 유효. → 그 문서를 읽는 사람이 오해하지 않게 이 표를 기준으로 볼 것.

---

## 그 외 계획↔코드 차이 (빌드/실행하며 발견·수정)

| # | 항목 | Phase 5 문서 | 실제 코드 | 상태/근거 |
|---|---|---|---|---|
| 1 | **빌드 방식** | CMake 가정(상세 없음) | CMake 링크가 nghttp2에서 깨짐 → `find_library`로 수정 + zlib/brotli/`/utf-8` 추가 | 수정됨. `cmake-guide.md` |
| 2 | **Logger `ERROR`** | (언급 없음) | Windows `ERROR` 매크로 충돌로 **빌드 자체 실패** → `#undef ERROR/DEBUG` | 첫 빌드에서 발견·수정 |
| 3 | **핸드셰이크/ALPN 순서** | (언급 없음) | 업스트림 먼저→**클라 먼저**로 재정렬(안 그러면 h2↔1.1 불일치로 응답 안 옴) | 수정됨. `build-and-progress.md` |
| 4 | **정수 파싱** | (언급 없음) | `std::stoll/stoi`는 비정상 입력에 예외→스레드 사망 → `parseLL` 안전 파서 | 수정됨 |
| 5 | **분석기 url 인자** | (walkthrough: Host/URL/Content-Type로 라우팅) | h1이 url 자리에 **host를 넘겨** URL 지문(`/backend-api/files`) 매칭 불가였음 → 요청 경로 전달로 수정 | 수정됨 |
| 6 | **매직넘버 검증(W9)** | plan: MIME↔실제포맷 교차검증 | PDF/PNG/JPEG만 구현, docx(=ZIP `PK`) 등은 통과 | 커버리지 제한(개선 후보) |
| 7 | **해시(W8)** | plan: "SHA-256 또는 기본 해시" | djb2 계열 의사 해시(16진 16자리) | 데모용. 진짜 SHA-256이면 별도 |
| 8 | **응답 body 캡처** | (언급 없음) | 무제한 축적 → 256KB 상한 | 수정됨 |
| 9 | **ChatGPT 전용 파서** | plan/walkthrough: `ChatGPTParser` | `parseChatGPTUpload`는 **스텁**(미구현, 로그만) | 계획대로 자리만; 실트래픽 캡처 후 구현 예정 |

## 검증 상태 요약 (계획 대비 "진짜 되는 것")
- ✅ 표준 multipart 추출 + 디스크 저장 + 매직/해시 (h1, 실측 바이트 일치)
- ✅ Content-Encoding **실해제** (h1, gzip 실측)
- ✅ h2 트래픽 중계·복호화 (실브라우저 페이지 로드)
- ⚠️ h2 파일 업로드 탐지 / h2 Content-Encoding 실해제 — 미검증·미구현
- ⚠️ ChatGPT 전용 파서 — 스텁

## 관련
- 빌드/검증 현황: `build-and-progress.md`
- CMake: `cmake-guide.md`
- 프로토콜 개념(6~9번): `../../proxy_beyond_docs/protocol-handling-6-9.md`
- 원 계획: `phase5-walkthrough.md`, `../../docs/ToInfinity/phase5-implementation-plan.md`
