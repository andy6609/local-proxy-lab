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
| **엔드포인트** | 한 번 업로드에 **탐지 2회** = 두 엔드포인트로 동시에 보냄 (재캡처 2026-07-21로 URL 확보): <br>① `claude.ai/api/organizations/{org}/conversations/{conv}/wiggle/upload-file` <br>② `claude.ai/api/organizations/{org}/convert_document` <br>({org}/{conv}=계정·대화별 UUID → 지문은 경로 패턴만 의미) |

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

## 재캡처 결과 (2026-07-21, 커밋 16b8940 반영)
- ✅ **이슈1 해결** — 한글 파일명 저장됨(`u8path`). ✅ **이슈2 해결** — 엔드포인트 URL 로깅됨(위 표 ①②).
- ⚠️ **이슈3 (신규) — 동시 쓰기 레이스로 저장 파일 손상.**
  - claude.ai가 한 업로드를 **두 엔드포인트(upload-file, convert_document)로 동시** 전송 → 프록시가
    **두 스레드에서 같은 출력 파일명에 동시 쓰기** → 저장본이 깨짐.
  - 증거: 파서 로그는 두 번 다 `13699 bytes 추출/저장 완료`인데, **디스크 파일은 19600 bytes 이고
    `DRMONE`(Fasoo DRM 암호문) 헤더**로 시작 → 파서가 쓴 것(13699 평문)과 디스크(19600 DRM)가 불일치.
    (두 쓰기가 뒤엉킴 + 업로드한 파일이 DRM본이었을 가능성)
  - 영향: **탐지·URL·메타데이터는 정확**하나 **"추출 파일 저장"은 신뢰 불가** → W8(바이너리 추출·해시검증) 전 필수 수정.
  - 수정안: 출력 파일명을 **캡처마다 유니크**(엔드포인트/카운터/타임스탬프 접두어) + 쓰기 보호(뮤텍스) → 동시 쓰기 충돌 제거.
  - ✅ **수정됨(2026-07-21):** 저장 파일명에 원자적 시퀀스 접두어(`<seq>_<이름>`) 적용(`std::atomic`). 검증: 같은 파일명 두 **동시** 업로드가 `1_race.txt`/`2_race.txt`로 **각각 원본과 바이트 일치**하게 저장됨(겹침 없음).

### 최종 재캡처 확인 + DRM 관측 (2026-07-21)
실제 claude.ai에 2회 업로드 → `1_`~`4_` **4개 파일 각각 온전히** 저장(레이스 없음). 이번 업로드 파일은 **DRM 보호본**이라 결과가 명확히 드러남:
- 4개 전부 **19856 bytes + `DRMONE ... This Document is encrypted and protected by Fasoo DRM`** 암호문.
  → 지난번 "13699 로그 vs 19600 파일" 불일치는 **레이스로 저장이 깨졌던 것**이고, 실제 업로드 본문은 DRM 암호문이었음.
- ⭐ **관측(DLP 근거):** 4개가 서로 **바이트 다름** — **같은 엔드포인트로 두 번 올린 것끼리도 다름(1≠3)**.
  = **Fasoo DRM이 읽을 때마다 다른 암호문을 생성**(랜덤 IV로 추정)한다는 뜻.
  → **DRM 보호 파일은 "내용 해시"로 식별·중복판정 불가**, 프록시가 안정적으로 얻는 건 **메타데이터(파일명·크기·타입·엔드포인트)뿐.**
  (평문 파일이면 본문까지 바이트 일치로 추출됨 — `build-and-progress.md` §DRM 대비 표 참조. 즉 **평문=내용까지 / DRM=메타데이터만**이 실측으로 재확인됨.)

## 다음
- **이슈3 수정** 후 claude.ai 재캡처 → 저장 파일 **바이트 무결성**까지 확인.
- 이어서 **ChatGPT / Gemini / 네이버**도 같은 방식으로 캡처 → 서비스별 비교 표.
