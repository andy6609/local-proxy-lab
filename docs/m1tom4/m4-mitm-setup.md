# M4/M5 — TLS MITM 셋업 가이드 (proxy_v4)

> proxy_v4 는 HTTPS 를 복호화한다(MITM). 이걸 빌드·실행하려면 v1~v3 에는 없던
> **3가지 준비**가 필요하다: ① OpenSSL 개발 라이브러리 ② Root CA 생성 ③ OS 신뢰 등록.
> (개념은 `m3-notes.md` §5, 코드는 `../proxy_v4/proxy_v4.cpp` 맨 위 주석)

---

## 0. 지금 막힌 이유 (IDE 빨간 줄)

`cannot open source file "openssl/ssl.h"` =
**OpenSSL 헤더/라이브러리가 안 깔려 있다.** Git Bash 에 있는 `openssl.exe` 는
명령줄 도구일 뿐, MSVC 로 컴파일·링크할 **개발 라이브러리(헤더 + .lib)** 가 아니다.
아래 1단계를 하면 사라진다.

---

## 1. OpenSSL 개발 라이브러리 설치 (둘 중 하나)

### 방법 A — vcpkg (권장: VS 와 자동 연동)
```powershell
# vcpkg 없으면 한 번만
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

# OpenSSL 설치 (x64)
C:\vcpkg\vcpkg.exe install openssl:x64-windows

# VS 전역 연동 (한 번만) — 이후 include/lib 경로 수동 설정 거의 불필요
C:\vcpkg\vcpkg.exe integrate install
```
- 설치 후 헤더: `C:\vcpkg\installed\x64-windows\include`
- .lib: `C:\vcpkg\installed\x64-windows\lib` (`libssl.lib`, `libcrypto.lib`)
- DLL: `C:\vcpkg\installed\x64-windows\bin` (실행 시 PATH 또는 exe 옆에 복사 필요)

### 방법 B — slproweb 설치 프로그램
1. https://slproweb.com/products/Win32OpenSSL.html 에서
   **"Win64 OpenSSL v3.x"** (Light 말고 **개발용 full**) 다운로드·설치.
2. 기본 경로: `C:\Program Files\OpenSSL-Win64`
   - include: `...\include`, lib: `...\lib\VC\x64\MD` (`libssl.lib`, `libcrypto.lib`)

---

## 2. Visual Studio 프로젝트 설정

proxy_v4 를 솔루션에 새 프로젝트로 추가한 뒤(빈 콘솔 앱 → `proxy_v4.cpp` 추가),
**프로젝트 속성(x64 / Debug+Release 둘 다)**:

| 항목 | 위치 | 값 (vcpkg integrate 했으면 생략 가능) |
|---|---|---|
| 추가 포함 디렉터리 | C/C++ → 일반 → Additional Include Directories | `C:\vcpkg\installed\x64-windows\include` |
| 추가 라이브러리 디렉터리 | 링커 → 일반 → Additional Library Directories | `C:\vcpkg\installed\x64-windows\lib` |
| 추가 종속성 | 링커 → 입력 → Additional Dependencies | (코드에 `#pragma comment(lib,...)` 있어서 보통 자동) |

- 코드 안에 `#pragma comment(lib, "libssl.lib")` 등이 이미 있어서 **lib 이름은 코드가 지정**.
  라이브러리 디렉터리만 잡아주면 됨.
- **.lib 이름이 다르면**(예 `ssl.lib`) `proxy_v4.cpp` 상단 `#pragma comment` 를 그 이름으로 수정.
- **한글 주석** 때문에 빌드 깨지면: C/C++ → 명령줄 → 추가 옵션에 `/utf-8` 추가 (v1 때와 동일).
- **DLL**: 실행 시 `libssl-3-x64.dll`, `libcrypto-3-x64.dll` 이 필요.
  exe 폴더(`x64\Debug\`)에 복사하거나 OpenSSL bin 을 PATH 에 추가.

---

## 3. Root CA 생성 (Git Bash 의 openssl CLI 로 충분)

proxy_v4 가 host 별 가짜 인증서를 서명할 **뿌리 인증서**를 만든다.
실행 작업 폴더(보통 `x64\Debug\`)에서, 또는 만들어서 거기로 복사:

```bash
# 1) Root CA 개인키
openssl genrsa -out rootCA.key 2048

# 2) Root CA 인증서 (자기서명, 10년)
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -out rootCA.crt \
  -subj "//CN=LocalProxy Lab Root CA\O=local-proxy-lab"
```
> Git Bash 에서 `-subj` 의 `/` 가 경로로 오인되면 위처럼 `//CN=...\O=...` 형태로.
> PowerShell 의 openssl 이면 `-subj "/CN=LocalProxy Lab Root CA/O=local-proxy-lab"`.

생성된 `rootCA.crt`, `rootCA.key` 를 **proxy_v4 실행 시 작업 폴더**에 둔다.
(코드의 `ROOT_CA_CERT`/`ROOT_CA_KEY` 가 상대경로 `rootCA.crt`/`rootCA.key`.
 헷갈리면 코드에서 절대경로로 바꿔도 됨.)

---

## 4. Root CA 를 Windows 신뢰 저장소에 등록

브라우저/curl 이 우리가 만든 가짜 leaf 를 믿게 하려면, 그 뿌리(rootCA.crt)를 신뢰시켜야 한다.

```powershell
# 현재 사용자 신뢰 루트에 등록 (관리자 권한 불필요)
certutil -addstore -user Root rootCA.crt
```
- 확인: `certmgr.msc` → 신뢰할 수 있는 루트 인증 기관 → 인증서 → "LocalProxy Lab Root CA"
- **테스트 끝나면 반드시 제거** (보안상 중요):
  ```powershell
  certutil -delstore -user Root "LocalProxy Lab Root CA"
  ```
- Firefox 는 OS 저장소를 안 쓰고 자체 저장소 → Firefox 설정에서 따로 import 해야 함.
  (Chrome/Edge/curl 은 OS 저장소 사용)

---

## 5. 실행 + 테스트

```powershell
# 프록시 실행 (작업폴더에 rootCA.crt/key + OpenSSL DLL 3개 있어야 함)
.\proxy_v4.exe

# 다른 터미널: HTTPS 가 '복호화'되는지 확인
#  ★ Windows curl 은 schannel 이라 폐기검사(revocation) 때문에 막힌다 -> --ssl-no-revoke 필수
curl.exe --ssl-no-revoke -x http://127.0.0.1:18080 https://httpbin.org/get

# 평문 HTTP 도 그대로 동작 (M2 경로)
curl.exe -x http://127.0.0.1:18080 http://httpbin.org/get
```

> **왜 `--ssl-no-revoke`?** 우리 leaf 인증서엔 CRL/OCSP(폐기 목록) 주소가 없다.
> Windows schannel(curl/Chrome/Edge 기반)은 "폐기 상태를 확인 못 하면 실패"가 기본이라
> `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` 로 막힌다. 폐기검사만 끄면 통과.
> (브라우저는 보통 폐기 확인 실패를 soft-fail 로 넘어가서 그대로 열린다. curl 이 더 엄격.)
> 인증서 체인 자체는 Root CA 등록으로 이미 신뢰됨 — 폐기검사만의 문제다.

**성공 신호:**
- curl 이 정상 JSON 응답을 받음 (인증서 에러 없이 — Root CA 신뢰됐으니).
- 프록시 콘솔에 **평문**으로 찍힘:
  ```
  [..:..:..] MITM  example  established (decrypting)
  [..:..:..] MITM  GET     httpbin.org/get -> 200 (256 bytes)
  ```
  → v3 에선 "tunnel open/closed (암호 바이트)"만 보였는데, v4 는 **method/URL/status 가 보인다.**
  이게 책임님 6주차 "암호화 통신이 프록시 내부에서 평문으로 분석" 의 증거.

- curl 만 빠르게: `--cacert rootCA.crt` 주면 OS 등록 없이도 검증 통과:
  ```powershell
  curl.exe --cacert rootCA.crt -x http://127.0.0.1:18080 https://httpbin.org/get
  ```

---

## 6. 안 될 때 체크리스트

| 증상 | 원인 / 해결 |
|---|---|
| `openssl/ssl.h` 못 찾음 | 1단계 미설치 또는 2단계 include 경로 누락 |
| 링커 `libssl.lib 못 찾음` | 2단계 lib 디렉터리 누락, 또는 .lib 이름 다름 → `#pragma comment` 수정 |
| 실행 즉시 `Root CA 로드 실패` | rootCA.crt/key 가 작업폴더에 없음(3단계) |
| 실행 직후 DLL 없음 팝업 | `libssl-3-x64.dll`/`libcrypto-3-x64.dll` 을 exe 옆에 복사(2단계 DLL) |
| curl `CRYPT_E_NO_REVOCATION_CHECK` (35) | schannel 폐기검사 → `--ssl-no-revoke` 추가 |
| curl `certificate problem` | 4단계 미등록, 또는 `--cacert rootCA.crt` 안 줌 |
| `bind failed: 10013` | 이전에 띄운 프록시(v1~v4)가 18080 점유 중 → 그 프로세스 종료 |
| `no OPENSSL_Applink` 로 즉시 죽음 | (해결됨) fopen 대신 BIO_new_file 사용. 직접 빌드 시 이 코드 유지 |
| 특정 사이트만 MITM 실패 | 인증서 피닝/HSTS (구글 일부·뱅킹). 의도된 한계 — 보고서에 기록 |
| 한글 깨짐/빌드 에러 | `/utf-8` 옵션 추가 |

---

## 관련 문서
- 실행 계획: `execution-plan-to-mitm.md` (M4/M5 정의)
- 이전 단계: `m1-tradeoffs.md`, `m2-notes.md`, `m3-notes.md`
- 코드: `../proxy_v4/proxy_v4.cpp` (맨 위 설계 주석 + 맨 아래 "한계" 블록)
