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

## 7. 끝나면 반드시 정리

프록시를 끈 뒤엔 **프록시 설정과 CA를 원복**해야 다른 통신이 정상이다.

```bat
:: 1) 프록시 끄기: Windows 설정 → 프록시 → 수동 프록시 설정 → 끄기

:: 2) 등록한 Root CA 제거
certutil -delstore -user Root "LocalProxy Dev CA"
```
> 프록시 exe는 콘솔에서 `Ctrl + C` 로 종료.

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
