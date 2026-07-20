# AI 서비스 업로드 지문 (실캡처 기록)

> 실브라우저(크롬)를 proxy_ToInfinity에 물려 실제 AI 서비스에 파일을 올리고, 프록시가
> **그 업로드를 어떻게 관측하는지**를 기록한다. (커리큘럼 7주차 "AI Agent/클라우드 서비스
> 업로드 요청 특성" = 서비스별 업로드 지문 표)

## 캡처 환경
- 프록시: `build/Release/proxy_ToInfinity.exe` (CMake 빌드), rootCA는 Windows 신뢰저장소 등록됨.
- 크롬: `--proxy-server=http://127.0.0.1:18080 --disable-quic`, 전용 프로필.
- **`--disable-quic` 필수:** claude.ai 업로드는 원래 HTTP/3(QUIC)를 타는데, QUIC은 UDP라 TCP MITM이
  못 잡는다. QUIC을 끄면 크롬이 **h2(TCP)로 폴백** → 프록시가 잡을 수 있게 됨.

---

## 1. claude.ai — 2026-07-21

**업로드 파일:** `C:\Exception\이것은 새로운 파일 이다.docx` (DRM 예외 폴더의 평문 .docx, 13699B)

### 지문 (요약)
| 항목 | 값 |
|---|---|
| 전송 | **HTTP/2** (h2) — QUIC 끈 상태 |
| 업로드 형식 | **표준 `multipart/form-data`** (정직한 웹폼 규격 → 코드 수정 없이 잡힘) |
| 파일명 | `이것은 새로운 파일 이다.docx` (한글, 정확히 추출) |
| 크기 | 13699 bytes (원본과 일치) |
| MIME | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| 매직넘버 | 일치 (`PK` = ZIP/OOXML, 예외폴더 평문이라 본문까지 보임) |
| **엔드포인트** | 한 번 업로드에 **탐지 2회** = 두 엔드포인트로 보냄 (이전 관찰: `.../wiggle/upload-file` → `.../convert_document`). ※ 현재 로그엔 URL 미기록 — 아래 이슈2 |

### 콘솔 로그 (실제로 찍힌 것, 2회 반복)
```
[INFO]  [Router] 표준 멀티파트 트래픽 식별. 표준 멀티파트 파서로 라우팅됨
[INFO]  [Parser] 파일명: 이것은 새로운 파일 이다.docx, 크기: 13699 bytes 추출 완료
[INFO]  [Verifier] 매직넘버 일치 확인 (application/vnd.openxmlformats-officedocument.wordprocessingml.document)
[INFO]  [Verifier] 추출된 파일 해시: 470e9be06e1e4343 (원본과 비교 요망)
[Parser] 파일 저장 실패: captured_files/이것은 새로운 파일 이다.docx     ← 이슈1
```
h2 연결이 뜬 관련 호스트(일부): `claude.ai`, `api.anthropic.com`, `a-api.anthropic.com`,
`assets.claude.ai`, `assets-proxy.anthropic.com` … (전부 h2).

### 의미
- **claude.ai는 표준 multipart** → 별도 전용 파서 불필요(표준 파서로 충분). (ChatGPT는 다를 수 있어 별도 캡처 필요.)
- 업로드가 **h2 + QUIC** 이라, 실서비스 관측엔 **QUIC 차단(→TCP 폴백) + h2 파싱**이 둘 다 필요함이 실증됨.
- 한 파일 → **2개 엔드포인트**(저장용 + 서버측 문서변환용) 패턴.

---

## 2. 이 캡처에서 드러난 문제 (트러블슈팅)

### 이슈1 — 한글(유니코드) 파일명 저장 실패
- 증상: `[Parser] 파일 저장 실패: captured_files/이것은 새로운 파일 이다.docx`. 탐지·추출·매직·해시는
  됐는데 **디스크 저장만 실패**, `captured_files/`가 빈 상태.
- 원인: Windows에서 `std::ofstream`의 **narrow(char) 경로**는 시스템 ANSI 코드페이지로 변환되는데,
  한글 UTF-8 파일명이 그 코드페이지로 표현 안 돼 파일 생성 실패.
- 영향: 파일 바이너리 추출(W8)에도 직결 → **반드시 수정.**
- 수정: 파일명을 **UTF-8로 해석하는 `std::filesystem::u8path`** 로 열어 유니코드 경로를 확실히 처리.
  (커밋 `<TBD>`)
- 참고: 이전 07-20 테스트(cl.exe, curl h1)에선 우연히 저장됐었으나, 유니코드 narrow 경로는 근본적으로
  불안정하므로 wide/u8path로 교체.

### 이슈2 — 업로드 엔드포인트 URL이 로그에 없음
- 증상: `[Router]/[Parser]`만 찍히고 **어느 URL로 올렸는지**가 안 남음 → 지문 표의 "엔드포인트" 칸을
  이 로그만으론 못 채움.
- 원인: 분석기(`routeToParser`)가 host+path를 로깅하지 않음.
- 수정: `[Router]` 로그에 **host+요청경로** 포함 → `claude.ai/api/.../upload-file` 형태로 남게.
  (커밋 `<TBD>`)

---

## 다음
- 위 두 수정 후 claude.ai 재캡처 → **URL 패턴 + 저장된 파일**까지 채워 이 표 완성.
- 이어서 **ChatGPT / Gemini / 네이버**도 같은 방식으로 캡처 → 서비스별 비교 표.
