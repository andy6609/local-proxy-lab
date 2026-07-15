# Windows 실행 가이드 — proxy_beyond (Plan A / Plan B) 처음부터 끝까지

> 이 프록시를 **처음 돌려보는 사람** 기준으로, 도구 설치 → 빌드 → 인증서 → 실행 → 로그 확인 → 정리까지 순서대로 적었다.
> 대상 파일: `proxy_beyond/proxy_plan_A.cpp`(검증됨), `proxy_beyond/proxy_plan_B.cpp`(h2, 미검증).
> 관련: 인증서 상세는 `docs/m4-mitm-setup.md`, 트랙 노트는 `proxy_beyond_docs/README.md`.

---

## 0. 이 프록시가 뭘 하는가 (1분 그림)

브라우저와 진짜 서버 사이에 끼어서, **HTTPS를 복호화해 평문 HTTP를 보고, 파일 업로드를 자동 탐지**하는 로컬 프록시다. 동작 흐름:

```
크롬 (프록시 설정: 127.0.0.1:18080)
   │  CONNECT claude.ai:443
   ▼
[이 프록시]  ← 가짜 인증서로 TLS를 벗김(복호화) → 평문에서 파일 업로드 탐지
   │  진짜 서버와 다시 TLS
   ▼
claude.ai (진짜 서버)
```

성공하면 콘솔에 요청 헤더 + `*** FILE UPLOAD DETECTED ... filename="..."` 로그가 뜬다.

- **Plan A**: HTTP/2를 1.1로 눌러서 처리. **이미 빌드·실행 검증됨.** 먼저 이걸로 툴체인이 정상인지 확인하는 걸 권장.
- **Plan B**: HTTP/2를 nghttp2로 그대로 파싱. **아직 미검증** — 첫 실행에서 디버깅이 필요할 수 있음.

---

## 1. 준비물 설치 (한 번만)

### 1-1. Visual Studio Build Tools (C++ 컴파일러)
- [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) 또는 **Build Tools for Visual Studio 2022** 설치
- 설치 시 **"C++를 사용한 데스크톱 개발(Desktop development with C++)"** 워크로드 체크
- 설치되면 시작 메뉴에 **"x64 Native Tools Command Prompt for VS 2022"** 가 생긴다 → **앞으로 빌드는 이 프롬프트에서** 한다 (컴파일러 경로가 자동 설정됨)

### 1-2. Git
- [git-scm.com](https://git-scm.com/download/win) 설치

### 1-3. vcpkg (OpenSSL / nghttp2 설치 도구)
"x64 Native Tools Command Prompt"에서:
```bat
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install openssl:x64-windows nghttp2:x64-windows
```
> 시간이 좀 걸린다(수 분~십수 분). 끝나면 `C:\vcpkg\installed\x64-windows\` 아래에 include / lib / bin / tools 가 생긴다.
> Plan A만 쓸 거면 `nghttp2`는 없어도 되지만, 어차피 Plan B도 할 거라 같이 깔아둔다.

---

## 2. 이 프로젝트(git) 받기

```bat
cd C:\
git clone https://github.com/andy6609/local-proxy-lab.git
cd local-proxy-lab
```
> 이미 clone 했다면 `git pull` 로 최신화.

---

## 3. 빌드

**"x64 Native Tools Command Prompt for VS 2022"** 에서 (일반 cmd 아님 주의):

```bat
cd C:\local-proxy-lab\proxy_beyond
```

### Plan A 빌드 (먼저 이걸로 검증 권장)
```bat
cl /nologo /EHsc /std:c++17 /utf-8 /I "C:\vcpkg\installed\x64-windows\include" ^
   proxy_plan_A.cpp /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib"
```
→ `proxy_plan_A.exe` 생성.

### Plan B 빌드 (h2)
```bat
cl /nologo /EHsc /std:c++17 /utf-8 /I "C:\vcpkg\installed\x64-windows\include" ^
   proxy_plan_B.cpp /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib"
```
→ `proxy_plan_B.exe` 생성.

> 라이브러리 이름(`libssl.lib` 등)은 코드 안 `#pragma comment(lib, ...)` 가 지정하므로, **include/lib 경로만** 주면 된다.
> `cannot open include file 'nghttp2/nghttp2.h'` 에러 → 1-3의 vcpkg install이 안 됐거나 `/I` 경로가 틀림.

---

## 4. 실행에 필요한 DLL + 인증서를 exe 옆에 두기

### 4-1. DLL 복사
`proxy_beyond` 폴더(exe가 있는 곳)로 아래 DLL을 복사한다. 원본 위치는 `C:\vcpkg\installed\x64-windows\bin\`:
```bat
copy C:\vcpkg\installed\x64-windows\bin\libssl-3-x64.dll    .
copy C:\vcpkg\installed\x64-windows\bin\libcrypto-3-x64.dll .
copy C:\vcpkg\installed\x64-windows\bin\legacy.dll          .
copy C:\vcpkg\installed\x64-windows\bin\nghttp2.dll         .
```
> 실행 시 `xxx.dll을 찾을 수 없습니다` 가 뜨면, 그 DLL을 `bin\` 에서 찾아 옆에 복사하면 된다.

### 4-2. Root CA 만들기 (한 번만)
프록시가 "가짜 인증서"를 서명할 때 쓸 **우리 Root CA**를 만든다. openssl은 vcpkg에 들어있다:
```bat
set OPENSSL=C:\vcpkg\installed\x64-windows\tools\openssl\openssl.exe

%OPENSSL% genrsa -out rootCA.key 2048
%OPENSSL% req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt ^
  -subj "/CN=LocalProxy Dev CA" ^
  -addext "basicConstraints=critical,CA:TRUE" ^
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```
→ `rootCA.crt`, `rootCA.key` 두 파일이 생긴다. **이 두 파일도 exe 옆(proxy_beyond)에** 있어야 한다(코드가 그 경로에서 로드).

### 4-3. Root CA를 Windows 신뢰 저장소에 등록
이걸 해야 브라우저가 우리 가짜 인증서를 믿는다(안 하면 인증서 경고로 막힘):
```bat
certutil -addstore -user Root rootCA.crt
```
> 현재 사용자 기준으로 등록. 크롬은 Windows 신뢰 저장소를 쓰므로 이걸로 충분. **등록 후 크롬 완전히 종료했다 재시작.**

---

## 5. 1차 확인 — curl로 프록시가 도는지 (브라우저 전에)

먼저 프록시 자체가 동작하는지 curl로 확인하면 문제를 분리하기 쉽다.

**터미널 1** — 프록시 실행:
```bat
cd C:\local-proxy-lab\proxy_beyond
proxy_plan_A.exe
```
`[proxy_plan_A] 18080 listening...` 이 뜨면 대기 중.

**터미널 2** — curl 테스트:
```bat
cd C:\local-proxy-lab\proxy_beyond
curl.exe --ssl-no-revoke --cacert rootCA.crt -x http://127.0.0.1:18080 https://httpbin.org/get
curl.exe --ssl-no-revoke --cacert rootCA.crt -x http://127.0.0.1:18080 -F "file=@rootCA.crt" https://httpbin.org/post
```
→ 두 번째 명령에서 **터미널 1(프록시)** 콘솔에 `*** FILE UPLOAD DETECTED ... filename="rootCA.crt"` 가 뜨면 **성공.** 여기까지 되면 복호화 + 업로드 탐지가 실제로 동작하는 것.

---

## 6. 브라우저로 실제 확인 (claude.ai 업로드)

### 6-1. 크롬(또는 시스템) 프록시 설정
Windows 설정 → **네트워크 및 인터넷 → 프록시 → 수동 프록시 설정 → 사용(켜기)**:
- 주소: `127.0.0.1`
- 포트: `18080`
- 저장

### 6-2. 업로드
1. 프록시 exe 실행 중인 상태에서 (Plan A 또는 Plan B)
2. 크롬에서 claude.ai 접속 → 파일 하나 업로드
3. **프록시 콘솔**을 본다.

### 6-3. 뭐가 보이면 성공인가
```
===== [MITM/1.1] >> REQUEST  POST claude.ai/api/.../upload =====
   host: claude.ai
   content-type: multipart/form-data; boundary=----xYz
   ...
  *** FILE UPLOAD DETECTED [MITM/1.1]  claude.ai/api/.../upload
      - field="file" filename="report.pdf" type="application/pdf"
```
- 헤더 블록(`>> REQUEST`) + `FILE UPLOAD DETECTED` 가 뜨면 목표 달성.
- Plan B면 태그가 `[MITM/h2]` 로 뜨고 `bridge established (decrypting h2)` 가 먼저 나온다.

> **주의:** claude.ai가 multipart가 아니라 다른 방식(raw PUT, JSON+base64)으로 올리면 `FILE UPLOAD DETECTED` 는 안 뜨고 `>> REQUEST` 헤더만 보인다. 그 Content-Type을 보고 "이 서비스는 이렇게 올리는구나"를 기록하는 게 다음 단계(서비스별 지문 조사)다.

---

## 6.5 실제 캡처 결과 — claude.ai 업로드 (2026-07-15, ✅ 성공)

> 위 §6 를 **실제로 수행한 결과.** 관련 사전분석: `claude-upload-capture-plan-0715.md`.
> (이번엔 시스템 프록시 대신 **프록시 물린 격리 Edge**(`--proxy-server=127.0.0.1:18080` + 별도 `--user-data-dir`)로 수행 —
> 시스템 설정 원복 불필요 + explicit proxy라 QUIC 이 자동 TCP 폴백되는 장점. 시스템 프록시로 해도 결과는 동일.)

### 결론: claude.ai 는 **정직한 multipart/form-data** → Plan A 가 그대로 잡는다

사전분석(`claude-upload-capture-plan-0715.md`)에서 "claude 가 multipart면 잡히고 아니면 파서 확장 필요"로 **열어뒀던 질문의 답**:
**multipart 였다.** 코드 수정 없이 `*** FILE UPLOAD DETECTED` 가 떴다. 업로드 한 번에 **두 개의 요청**이 관측됨:

```
# ① 실제 파일 저장 엔드포인트
*** FILE UPLOAD DETECTED  claude.ai/api/organizations/{org}/conversations/{conv}/wiggle/upload-file
    multipart/form-data; boundary=----WebKitFormBoundary........
    - field="file" filename="…​.docx" type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"

# ② 서버측 문서 변환 엔드포인트 (업로드 직후 같은 파일을 한 번 더 받음)
*** FILE UPLOAD DETECTED  claude.ai/api/organizations/{org}/convert_document
    multipart/form-data; boundary=----WebKitFormBoundary........
    - field="file" filename="…​.docx" type="…​wordprocessingml.document"
```

### 서비스별 업로드 지문표 (첫 실제 항목)

| 서비스 | 전송 | 방식 | 엔드포인트 | Content-Type | 파일 필드 | Plan A 탐지 |
|---|---|---|---|---|---|---|
| **claude.ai** | h2→(ALPN)1.1 | 2단계 POST | `.../conversations/{conv}/wiggle/upload-file` → `.../convert_document` | `multipart/form-data` | `file` (filename·MIME 보존) | ✅ 코드수정 없이 |

### 확인된 분석 포인트 (가이드 §6 / capture-plan 예측 vs 실제)

- **전송 프로토콜:** 로그에 `established (decrypting, alpn=http/1.1)` — **Plan A ALPN 다운그레이드 정상 작동.**
  claude.ai 는 Cloudflare 뒤라 QUIC(h3) 을 먼저 시도하지만, explicit proxy 를 켜니 **UDP QUIC 이 안 통해 자동 TCP 폴백** →
  capture-plan 1단계 예측대로. (그래서 `chrome://flags` h3 비활성화 **안 해도** 잡혔다. 시스템 프록시로 했을 때 QUIC 을 고집하면 그때 h3 끄기.)
- **인증서 핀닝:** claude.ai / a-api.anthropic.com 모두 우리 rootCA 로 **정상 복호화됨(핀닝 차단 없음).** handshake 실패 없음.
- **업로드 방식:** raw PUT / presigned-S3 / JSON+base64 가 아니라 **전통적 multipart** → `scanMultipart` 가 파일명·MIME 바로 추출. (capture-plan 2단계 표의 "✅ 바로 잡힘" 케이스)
- **2단계 업로드:** `wiggle/upload-file`(저장) + `convert_document`(서버측 파싱) 로 **같은 파일이 두 번** 지나감. 탐지도 2번.
- **파일 내용(평문/DRM):** 올린 파일이 Fasoo **예외 폴더의 새 .docx**(평문)라 본문은 정상 `PK`(.docx=ZIP) 였을 것.
  단, Plan A 로그는 **메타데이터만** 찍어 본문은 직접 안 보인다 → 본문 평문/DRM 자동판별은 별도 작업(프록시가 body 앞부분 덤프 or DRM 시그니처 플래그).

### 주의 (재현 시)
- 격리 Edge 프로필로 하면 claude.ai **재로그인 필요.** 로그(`proxyA.log`)에 **로그인 세션 쿠키가 평문**으로 남으므로,
  실험 후 로그 삭제 + (원하면) 격리 프로필 폴더 삭제로 흔적 정리.
- 엔드포인트의 `{org}`/`{conv}` 는 계정·대화별 UUID. 지문으로는 **경로 패턴**(`/wiggle/upload-file`, `/convert_document`)만 의미 있음.

---

## 6.6 Plan B 실험 — 진짜 HTTP/2 복호화 검증 (다음 목표)

> §6.5는 **Plan A** 결과다 = h2를 **1.1로 눌러앉혀서**(다운그레이드) 잡은 것. `alpn=http/1.1`.
> 이건 "1.1 경로 + 탐지 로직"을 증명했지, **"진짜 h2를 그대로 복호화"** 를 증명한 게 아니다.
> **Plan B의 목표 = 다운그레이드 없이, 크롬이 claude.ai와 진짜 HTTP/2로 말하는 걸 nghttp2로 복호화하고도 업로드가 잡히나.**

### 왜 굳이 Plan B (1.1로도 잡혔는데)
- h2 와이어는 **바이너리 프레임 + HPACK 헤더압축 + 스트림 멀티플렉싱**이라 1.1 텍스트 파서로는 못 읽는다 → nghttp2 필요.
- 다운그레이드(Plan A)는 상대가 1.1을 **거부하면 실패**한다(h2-only 클라/서버). Plan B는 h2를 정면으로 풀어서 그 한계가 없다.
- 이력서 관점: "HTTP/2를 nghttp2로 실제 복호화"가 "전부 1.1로 눌러버림"보다 훨씬 강한 결과물.
- **단, 논리적 내용(filename·multipart·업로드)은 1.1과 동일**하게 나온다. h2는 전송만 바꿨지 HTTP 의미는 그대로라서. → 탐지 로그는 비슷하게 보이고, 다른 건 "거기 도달하는 기계장치".

### 준비 (Plan A 했으면 대부분 재사용)
- `proxy_plan_B.exe` 빌드 (§3의 Plan B 커맨드)
- **`nghttp2.dll` 이 exe 옆에** 있어야 함 (§4-1). ← Plan A엔 없어도 되지만 Plan B는 필수
- `rootCA.crt/key` + 신뢰등록은 Plan A와 공유 (이미 됨)

### 실행
```bat
cd C:\local-proxy-lab\proxy_beyond
proxy_plan_B.exe
```
그 다음 §6.5와 동일하게 — 격리 Edge(`--proxy-server=127.0.0.1:18080`) 또는 시스템 프록시로 claude.ai 접속 → 파일 업로드.
(Plan B는 h2를 우선 협상하므로 특별히 뭘 더 할 것 없이 그냥 올리면 된다. explicit proxy라 QUIC은 여전히 TCP 폴백 → 그 위에서 h2 협상.)

### 성공 판정 — Plan A와 **뭐가 달라야** 하나
로그에서 이 세 개를 확인한다:
```
MITM/h2 claude.ai bridge established (decrypting h2)      ← ★ "h2"로 떠야 진짜
===== [MITM/h2] >> REQUEST  POST claude.ai/.../upload-file =====   ← 태그가 [MITM/h2]
  *** FILE UPLOAD DETECTED [MITM/h2]  ...  filename="..."
```
- 태그가 `[MITM/1.1]`이 아니라 **`[MITM/h2]`**, `alpn`이 `http/1.1`이 아니라 **`h2`** → 이게 뜨면 **진짜 h2 복호화 성공.**
- 여기까지 되면 want 1(h2 제대로) 확보. claude.ai는 이미 multipart로 확인됐으니 탐지도 그대로 뜰 것.

### 흔한 실패 3가지 + 진단 (Plan B는 미검증이라 각오)
| 증상 | 원인 / 다음 |
|---|---|
| `bridge established (decrypting h2)` 는 떴는데 그 뒤 `>> REQUEST` 가 **안 나오고 멈춤/hang** | **nghttp2 data provider resume 타이밍 버그.** Plan B의 핵심 디버깅 지점. → 로그를 established 직후까지 **그대로 캡처**해서 가져올 것 |
| 실행 중 **crash** | 콜백 널포인터/스트림 매핑 문제. **크래시 직전 마지막 로그 줄**을 확인 |
| 태그가 `[MITM/h2]` 가 아니라 `[MITM/1.1]` 로 뜸 | h2가 아니라 1.1로 붙음. 브라우저가 h2 제안을 안 했거나 서버가 1.1로 내려앉음. claude.ai는 h2 지원이라 보통 h2로 떠야 정상 → `alpn` 로그 확인 |
| `ALPN mismatch ... translation not implemented` 로 종료 | 클라 h2 ↔ 서버 1.1(또는 반대) 불일치. Plan B의 문서화된 한계. claude.ai엔 드묾 |

### 막히면
위 표의 어느 증상이든 **로그를 그대로 복사**해서 가져오면 같이 잡는다. 특히 **"established 떴는데 요청 안 뜸"** 이면 resume 타이밍이라 `cb_on_data_chunk` / `cb_on_frame_recv`의 `nghttp2_session_resume_data` 호출 부분을 함께 손봐야 한다.

---

## 6.7 실제 시도 결과 — Plan B (2026-07-15, ⚠️ 부분 성공)

> §6.6 을 **실제로 돌린 결과.** "빌드/기동/h2 복호화는 됐고, 응답 방향에서 막혔다."

### 빌드 — 처음으로 컴파일 성공 (수정 2개 필요했음)
Plan B 는 그동안 "미검증"이었는데, MSVC 로 빌드하니 두 곳이 걸렸다. 둘 다 고쳐서 **첫 빌드 성공**:
1. **`ssize_t` 미정의 (nghttp2.h C2065):** nghttp2 는 소비자 빌드에서 `ssize_t` 기반 콜백 typedef 를 그대로
   컴파일하는데 MSVC 엔 `ssize_t` 가 없다. → `#include <nghttp2/nghttp2.h>` **직전에** 아래 추가:
   ```cpp
   #include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
   ```
2. **`dumpHeadView` 인자 타입:** 호출부가 동적 `std::string`("<< RESPONSE (" + st + ")")을 넘기는데
   함수는 `const char* dir` 를 받아 C2664. → 시그니처를 `const std::string& dir` 로 변경(리터럴 호출도 그대로 됨).

### 실행 결과 — h2 복호화·요청 방향은 됨, 응답 방향이 깨짐
격리 브라우저(`--proxy-server`)로 claude.ai 접속 시 로그:
```
MITM/h2 claude.ai bridge established (decrypting h2)     ← ✅ 진짜 h2 복호화 성공 (다운그레이드 아님)
===== [MITM/h2] >> REQUEST  GET claude.ai/ =====         ← ✅ h2 요청을 헤더까지 정확히 디코드
   (…그런데 이 요청에 대한  << RESPONSE claude.ai/  가 로그에 없음)
```
- **브라우저 결과:** `ERR_HTTP2_PROTOCOL_ERROR` → claude.ai **페이지 백지.**
- **원인:** Plan B 가 upstream 응답을 **브라우저로 h2 재조립해 되돌려주는 부분(응답 방향)** 이 깨져,
  깨진 프레임을 받은 브라우저가 스트림을 끊음. (요청 방향은 정상, 응답 방향만 버그)
- **완전히 죽은 건 아님:** 같은 시각 `nav-edge.smartscreen…` 의 **작은 응답(400)** 은 브라우저로 잘 돌아갔다.
  → 응답 번역이 **특정 케이스(큰 응답/특정 헤더·본문)** 에서만 깨지는 것으로 보임.

### 그래서 = 업로드 캡처의 딜레마
- 업로드 탐지 로직은 **요청 방향**(작동함)에 있다 → 원리상 업로드 요청이 나가면 Plan B 도 잡는다.
- 하지만 claude.ai 는 JS 로 그려지는 웹앱(SPA)이라 **페이지(응답)가 떠야** 채팅창·업로드 버튼이 생긴다.
- 응답이 깨져 페이지가 백지 → 업로드 UI 없음 → **업로드 요청 자체가 발생 안 함** → 캡처할 게 없음.
- **한 줄:** "탐지 능력은 있는데, 페이지가 안 떠서 업로드까지 도달을 못 한다."

### 왜 Plan A 는 되는데 Plan B 는 안 되나
| | Plan A | Plan B |
|---|---|---|
| h2 처리 | ALPN 으로 **1.1 다운그레이드(회피)** | **진짜 h2 파싱** |
| 응답→브라우저 | 검증된 1.1 중계 → **정상** | h2 재조립 → **버그(깨짐)** |
| 페이지 렌더 | ✅ 뜸 (업로드까지 됨) | ❌ 백지 |
Plan A 는 어려운 **h2 응답 재조립을 아예 안 해서**(1.1로 내려서) 문제가 안 생긴다. Plan B 는 그걸 정면으로
해야 해서 거기서 막힌 것.

### ⚠️ 실험하다 겪은 함정 — 반드시 "프록시 물린 창"에서 업로드
- 우리 프록시는 **`--proxy-server` 로 띄운 그 격리 창의 트래픽만** 본다.
- 평소 쓰는 크롬/엣지(이미 로그인된)에서 업로드하면 **프록시를 안 타서 로그에 아무것도 안 잡힌다.**
  (실제로 한 번 이것 때문에 "업로드했는데 왜 안 잡히지?" 로 헤맴 — 알고 보니 일반 크롬으로 올린 것이었음.)
- 이미 실행 중인 브라우저에 `--proxy-server` 를 나중에 붙일 수 없다(새 플래그 무시됨). **별도 `--user-data-dir`
  로 새로 띄운 창**에서 해야 프록시를 탄다(그래서 재로그인 필요). 크롬/엣지 둘 다 동일.

### 다음 디버깅 지점 (응답 방향)
`<< RESPONSE` 가 안 찍히는 지점부터. 후보:
- `nghttp2_submit_response` / data provider(`respBodyRead`) 흐름 — 응답 body 를 h2 DATA 로 내보내는 부분
- `nghttp2_session_resume_data` 타이밍(백프레셔/재개), 응답 헤더 번역(대소문자/hop-by-hop/`:status`)
- 작은 응답은 되고 큰 응답은 깨지는 패턴 → **본문 스트리밍/flow-control** 쪽 의심

> ★ 이 디버깅은 **별도 hard-task 문서**로 깊게 정리해뒀다: **`resume-hard-task.md`**
> (증상·재현·코드 지도(함수/줄)·가설 우선순위·디버깅 순서·성공 기준). 응답 경로 작업은 거기부터 시작.

---

## 7. 끝나면 반드시 정리

프록시를 끈 뒤엔 **프록시 경로와 흔적을 원복**해야 다른 통신·보안이 정상이다.

### 7-1. 공통 (둘 다 해당)
```bat
:: 프록시 exe 종료: 콘솔에서 Ctrl + C  (또는  taskkill /IM proxy_plan_A.exe /F)

:: 캡처 로그 삭제 — 로그인 세션 쿠키가 평문으로 남으므로 반드시 지운다
del proxyA.log
```

### 7-2. 프록시 연결 방식별 원복
- **시스템 프록시로 했을 때:** Windows 설정 → 네트워크 및 인터넷 → 프록시 → **수동 프록시 설정 → 끄기.**
- **격리 Edge(`--proxy-server` 플래그)로 했을 때(§6.5 방식):** 끌 시스템 프록시가 **없다.** 그냥 그 **창을 닫으면** 끝.
  로그인 흔적까지 지우려면 격리 프로필 폴더(`--user-data-dir` 로 준 경로)를 삭제.

### 7-3. Root CA 신뢰 — 선택 (계속할지 vs 원복할지)
- **계속 실험할 거면 그대로 둬도 된다.** (매번 재등록 안 해도 됨 = 편함)
- **원복하려면**(보안상 권장 — 신뢰된 MITM 루트 CA를 남겨두는 셈이므로):
  ```bat
  certutil -delstore -user Root "LocalProxy Dev CA"
  ```
  단, 지우면 **다음 실행 때 §4-3 의 `certutil -addstore` 로 재등록**해야 브라우저가 다시 믿는다.
  (트레이드오프: 남기면 편하지만 신뢰저장소에 우리 CA가 계속 있음 / 지우면 안전하지만 다음에 재등록.)

---

## 8. 자주 나는 문제 (Troubleshooting)

| 증상 | 원인 / 해결 |
|---|---|
| `cannot open include file 'nghttp2/nghttp2.h'` | vcpkg install 안 됨 or `/I` 경로 오타. 1-3 재확인 |
| 빌드는 됐는데 실행 즉시 종료 + `Root CA 로드 실패` | `rootCA.crt/key` 가 exe 옆에 없음. 4-2 위치 확인 |
| `libssl-3-x64.dll을 찾을 수 없습니다` 등 | 4-1 DLL 복사 누락. 해당 DLL을 `bin\` 에서 복사 |
| 브라우저에 인증서 경고가 뜸 | 4-3 CA 신뢰 등록 안 됨, 또는 크롬 재시작 안 함 |
| 프록시 설정했는데 claude.ai가 안 잡힘 | QUIC(h3) 때문일 수 있음. `chrome://flags` → "Experimental QUIC protocol" → **Disabled** 후 크롬 재시작. (프록시 걸면 대개 자동 TCP 폴백이라 보통은 그냥 됨) |
| Plan B: `bridge established` 는 뜨는데 요청 로그가 안 뜸 / 멈춤 | Plan B 미검증 이슈(nghttp2 resume 타이밍). **먼저 Plan A로 테스트**해서 툴체인·인증서는 정상인지 분리한 뒤, Plan B 브릿지만 따로 디버깅 |
| `ALPN mismatch ... translation not implemented` 로 종료 | 클라와 서버가 서로 다른 프로토콜 협상(h2↔1.1). Plan B 한계. 대형 사이트는 드묾 |

---

## 9. 요약 체크리스트

```
[ ] VS Build Tools(C++) + Git 설치
[ ] vcpkg + openssl:x64-windows + nghttp2:x64-windows
[ ] git clone / pull
[ ] x64 Native Tools 프롬프트에서 cl 로 proxy_plan_A.exe (또는 _B) 빌드
[ ] DLL 4개 + rootCA.crt/key 를 exe 옆에 배치
[ ] certutil 로 rootCA.crt 신뢰 등록 + 크롬 재시작
[ ] curl 로 1차 확인 (FILE UPLOAD DETECTED 뜨나)
[ ] 크롬 프록시 127.0.0.1:18080 설정 → claude.ai 업로드 → 콘솔 확인
[ ] 끝나면 프록시 끄기 + certutil -delstore 로 CA 제거
```

### Plan B (진짜 h2) 실험 체크리스트 — §6.6
```
[ ] proxy_plan_B.cpp 빌드 (§3) + nghttp2.dll 을 exe 옆에 (§4-1)
[ ] proxy_plan_B.exe 실행 → claude.ai 파일 업로드
[ ] 로그에 [MITM/h2] + "bridge established (decrypting h2)" + alpn=h2 뜨나 확인
[ ] FILE UPLOAD DETECTED [MITM/h2] 뜨면 성공 (want 1 = h2 제대로 확보)
[ ] established 떴는데 요청 안 뜨면 → resume 타이밍 버그, 로그 그대로 캡처
```
