<#
================================================================================
 run_browser_test.ps1  —  Plan A 실제-브라우저 업로드 탐지 실험 재현 스크립트
================================================================================

# 이게 뭔가 (한 줄)
평범한 Edge 브라우저를 우리 MITM 프록시(`proxy_plan_A.exe`)에 물려서,
**실제 브라우저의 HTTPS 파일 업로드**를 프록시가 복호화·탐지하는지(=Fiddler 급) 눈으로 확인하는 실험.

# 왜 이걸 하게 됐나 (과정 narrative)
1. Plan A 코드(ALPN 다운그레이드 + 업로드 탐지)는 `curl`로는 이미 검증돼 있었다.
2. 그런데 멘토 요구 = "**Fiddler처럼 실제 트래픽**". curl 이 아니라 **진짜 브라우저 TLS 스택**으로도
   되는지 봐야 했다. (브라우저는 기본 HTTP/2 선호 → Plan A 가 ALPN 에서 http/1.1 로 눌러 앉히는지 실증 필요)
3. 그래서: 평범한 Edge 를 `--proxy-server` 플래그로 프록시에 물리고(브라우저 개조 아님),
   `upload_test.html`(→ httpbin.org/post 로 multipart 업로드하는 로컬 페이지)로 파일을 올려봤다.
4. 결과 = **성공.** 프록시 로그에 `*** FILE UPLOAD DETECTED ... filename=... type=...` 가 찍혔고,
   TLS 도 `alpn=http/1.1` 로 내려앉아 우리 1.1 파서가 평문으로 읽었다. (피들러가 하는 것과 동일)

# 곁가지로 발견한 것 (중요 — Fasoo DRM)
- 호스트에 **Fasoo DRM** 이 깔려 파일이 투명 암호화됨 → 업로드한 워드 파일 본문이 네트워크에
  `...encrypted and protected by Fasoo DRM` **암호문**으로 나갔다. (프록시는 메타데이터만 봄, 내용 X)
- **Fasoo 예외(exception) 폴더** 에서 **새로 만든** 파일은 평문 → 네트워크에 `PK♥♦`(정상 .docx=ZIP)로
  나갔고 프록시가 **내용까지** 봤다. → 그래서 clean VM 없이 호스트에서 개발 가능. (README §7 참조)
- 함정: 예외 폴더는 "**거기서 새로 생성**"에만 적용. 이미 암호화된 파일을 옮겨도 복호화 안 됨.

# 사전 준비 (한 번만)
- OpenSSL DLL 3개(`libssl-3-x64.dll`, `libcrypto-3-x64.dll`, `legacy.dll`) + `rootCA.crt`/`rootCA.key`
  가 이 폴더(exe 옆)에 있어야 함. (이미 있음)
- rootCA 를 OS 신뢰 등록:  `certutil -addstore -user Root rootCA.crt`
  (테스트 끝나면 제거:      `certutil -delstore -user Root "LocalProxy Lab Root CA"`)
- 빌드 방법은 README §4 / `../docs/m4-mitm-setup.md` 참고.

# 사용법
    powershell -ExecutionPolicy Bypass -File .\run_browser_test.ps1
그럼 (1) 프록시가 새 콘솔 창에서 뜨고(라이브 로그=피들러 세션 목록 역할),
     (2) 프록시 물린 격리 Edge 가 테스트 페이지를 연다. 파일 골라 [업로드] 누르면 프록시 창에 탐지 로그.

# ★ 맥(macOS)에서 이 프로젝트를 다시 볼 때
- 이 `.ps1` 과 `proxy_plan_A.cpp` 는 **Windows 전용**이다:
  코드가 WinSock2(`WinSock2.h`/`ws2_32.lib`) + `#pragma comment` 링커 지시자에 의존.
  Edge `--proxy-server` 실행법도 Windows 기준. → 맥에선 그대로는 컴파일/실행 안 됨.
- 맥에서 재현하려면: 소켓부를 POSIX 로 포팅(또는 별도 빌드) + TLS MITM 로직(OpenSSL)은 크로스플랫폼이라 유지 가능.
  브라우저는 맥용 Chrome/Edge 를 `--proxy-server=127.0.0.1:18080` 로 실행.
- 다만 **최종 타깃이 Windows(Fasoo/WFP)** 라 맥 포팅은 권장 안 함. 이 파일은 "당시 무엇을·왜 했는지"
  기록용으로 읽으면 됨. (실제 재현은 Windows 에서)
================================================================================
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- 설정 ----
$ProxyExe  = Join-Path $here 'proxy_plan_A.exe'
$TestPage  = Join-Path $here 'upload_test.html'
$ProxyAddr = '127.0.0.1:18080'
$EdgeProfile = Join-Path $env:TEMP 'edge-proxy-profile'   # 격리 프로필(원래 Edge 설정 안 건드림)

# ---- 사전 점검 ----
if (-not (Test-Path $ProxyExe)) { throw "프록시 실행파일이 없습니다: $ProxyExe (README §4 로 빌드하세요)" }
if (-not (Test-Path $TestPage)) { throw "테스트 페이지가 없습니다: $TestPage" }

$edge = @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw "msedge.exe 를 찾지 못했습니다. Chrome 을 쓰려면 경로만 바꾸세요(플래그 동일)." }

# rootCA 신뢰 등록 여부 안내(강제는 안 함)
$trusted = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
           Where-Object { $_.Subject -like '*LocalProxy*' }
if (-not $trusted) {
    Write-Warning "rootCA 가 신뢰 저장소에 없습니다. 인증서 에러가 나면 먼저 실행:  certutil -addstore -user Root `"$here\rootCA.crt`""
}

# ---- 1) 프록시를 새 콘솔 창에서 실행 (라이브 로그 = 피들러 세션 목록 역할) ----
Write-Host "[1/2] 프록시 실행: $ProxyExe (새 창, 포트 $ProxyAddr)" -ForegroundColor Cyan
Start-Process -FilePath $ProxyExe -WorkingDirectory $here
Start-Sleep -Milliseconds 800   # 리슨 시작 대기

# ---- 2) 프록시 물린 격리 Edge 로 테스트 페이지 열기 ----
$pageUrl = 'file:///' + ($TestPage -replace '\\', '/')
Write-Host "[2/2] Edge 실행 → $pageUrl" -ForegroundColor Cyan
& $edge `
    --user-data-dir="$EdgeProfile" `
    --no-first-run --no-default-browser-check `
    --proxy-server="$ProxyAddr" `
    "$pageUrl"

Write-Host ""
Write-Host "준비 완료. Edge 창에서 파일을 고르고 [업로드] 를 누르면 프록시 창에 다음이 찍힙니다:" -ForegroundColor Green
Write-Host '    *** FILE UPLOAD DETECTED [MITM]  httpbin.org/post' -ForegroundColor Green
Write-Host '        - field=... filename=... type=...' -ForegroundColor Green
Write-Host ""
Write-Host "평문 vs DRM 확인 팁: httpbin 응답의 files.myfile 값이" -ForegroundColor Yellow
Write-Host "  'PK...'(정상 .docx=ZIP) 로 시작하면 평문,  '...Fasoo DRM' 이면 DRM 암호문." -ForegroundColor Yellow
