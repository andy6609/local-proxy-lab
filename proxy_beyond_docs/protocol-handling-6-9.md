# Plan A 로그 기록 — 프로토콜 처리 관찰 (weeks 6–9)

> Plan A(`proxy_plan_A.cpp`, ALPN로 h2→http/1.1 다운그레이드 + 업로드 탐지)를 돌렸을 때
> **콘솔에 실제로 찍힌 로그**를 그대로 남겨둔다. "정상 동작이 어떻게 보이는가"의 기준.
> 이 세션(2026-07-14~16)에서 curl·실브라우저(Edge)로 캡처한 것. Plan B와의 대비는 맨 아래.

---

## 0. 로그 읽는 법 (Plan A 태그 = `[MITM]`)

| 로그 줄 | 의미 |
|---|---|
| `MITM host:443 established (decrypting, alpn=http/1.1)` | TLS 복호화 시작. **`alpn=http/1.1`** = Plan A가 h2를 1.1로 눌러앉힘 |
| `===== [MITM] >> REQUEST  host/path =====` | 복호화된 **요청** 헤더 덤프 시작 |
| `----- [MITM] << RESPONSE  (200) -----` | 복호화된 **응답** 헤더 덤프 |
| `*** FILE UPLOAD DETECTED [MITM] ...` | multipart/form-data 감지 → 파일 필드/이름/타입 추출 |
| `[..] MITM  GET  host/path -> 200 (N bytes)` | 한 exchange 요약(메서드·URL·상태·바이트) |
| `MITM host:443 closed` | 연결 종료 |

기동 배너: `[proxy_plan_A] 18080 listening... (MITM + ALPN->http/1.1 + upload detect)`

---

## 1. curl — 단순 GET (httpbin)

명령: `curl.exe --ssl-no-revoke --cacert rootCA.crt -x http://127.0.0.1:18080 https://httpbin.org/get`

```
[13:42:42] MITM httpbin.org:443 established (decrypting, alpn=http/1.1)

===== [MITM] >> REQUEST  httpbin.org/get =====
GET /get HTTP/1.1
  Host: httpbin.org
  User-Agent: curl/8.19.0
  Accept: */*
----- [MITM] << RESPONSE  (200) -----
HTTP/1.1 200 OK
  Date: Tue, 14 Jul 2026 04:42:43 GMT
  Content-Type: application/json
  Content-Length: 254
  Connection: keep-alive
  Server: gunicorn/19.9.0
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Credentials: true
[13:42:43] MITM  GET     httpbin.org/get -> 200 (254 bytes)
[13:42:43] MITM httpbin.org:443 closed
```
→ HTTPS인데도 요청/응답이 **평문으로** 보인다(복호화 성공). 이게 "Fiddler처럼 보인다"의 최소 증거.

---

## 2. curl — multipart 파일 업로드 (httpbin) → FILE UPLOAD DETECTED

명령: `curl.exe ... -F "file=@hello.txt" https://httpbin.org/post`

```
[13:42:44] MITM httpbin.org:443 established (decrypting, alpn=http/1.1)

===== [MITM] >> REQUEST  httpbin.org/post =====
POST /post HTTP/1.1
  Host: httpbin.org
  User-Agent: curl/8.19.0
  Accept: */*
  Content-Length: 371
  Content-Type: multipart/form-data; boundary=------------------------HIvaqRBdk2Cgcb1GCS5T3o
  *** FILE UPLOAD DETECTED [MITM]  httpbin.org/post
      multipart/form-data; boundary=------------------------HIvaqRBdk2Cgcb1GCS5T3o
      - field="file" filename="hello.txt" type="text/plain"
----- [MITM] << RESPONSE  (200) -----
HTTP/1.1 200 OK
  Date: Tue, 14 Jul 2026 04:42:45 GMT
  Content-Type: application/json
  Content-Length: 560
  Connection: keep-alive
  Server: gunicorn/19.9.0
[13:42:46] MITM  POST    httpbin.org/post -> 200 (560 bytes)
[13:42:46] MITM httpbin.org:443 closed
```

다른 파일로도 동일하게(재빌드 검증 시):
```
*** FILE UPLOAD DETECTED [MITM]  httpbin.org/post
    multipart/form-data; boundary=------------------------pJpVFDoqe0HJ8xzn41DSGM
    - field="file" filename="rootCA.crt" type="application/octet-stream"
```

---

## 3. 실제 브라우저(Edge) — claude.ai 파일 업로드 (핵심 성과)

프록시 물린 Edge에서 claude.ai에 `.docx` 업로드 시. **claude.ai는 정직한 multipart**라 코드 수정 없이 잡힘.
업로드 한 번에 **두 엔드포인트**(파일 저장 → 서버측 문서 변환)가 관측됨:

```
[..] MITM claude.ai:443 established (decrypting, alpn=http/1.1)

*** FILE UPLOAD DETECTED [MITM]  claude.ai/api/organizations/{org}/conversations/{conv}/wiggle/upload-file
    multipart/form-data; boundary=----WebKitFormBoundaryQtNn8BJwsW7jWTrk
    - field="file" filename="이것은 새로운 파일 이다.docx" type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"

*** FILE UPLOAD DETECTED [MITM]  claude.ai/api/organizations/{org}/convert_document
    multipart/form-data; boundary=----WebKitFormBoundaryitk66cb21eGnnBor
    - field="file" filename="이것은 새로운 파일 이다.docx" type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
```
→ 한글 파일명·정확한 MIME까지 추출. (`{org}`/`{conv}`는 계정·대화별 UUID — 지문으론 경로 패턴만 의미.)
자세한 분석·지문표는 `windows-run-guide.md` §6.5.

### (곁가지) DRM 관측
같은 파일이라도 **Fasoo DRM으로 암호화된 상태**면 업로드 본문이 `...encrypted and protected by Fasoo DRM`
암호문으로 나가고, **예외 폴더의 새 평문 파일**이면 `PK`(정상 .docx=ZIP)로 나간다. 프록시는 메타데이터는
항상 잡지만 본문 내용은 DRM 여부에 따라 갈림. (README §6, windows-run-guide §6.5 참조)

---

## 4. 대비 — Plan B(진짜 h2)에서는 로그가 어떻게 다른가

| | Plan A | Plan B |
|---|---|---|
| 태그 | `[MITM]` | `[MITM/h2]`(h2) / `[MITM/1.1]`(fallback) |
| established | `... (decrypting, alpn=http/1.1)` | `... bridge established (decrypting h2)` |
| 현재 상태 | ✅ 요청·응답·업로드 다 정상 | ⚠️ upstream이 요청을 `RST_STREAM err=1`로 거절 → 응답 안 옴 (디버깅 중) |

Plan B 디버깅 경과는 `plan-b-h2-debug-progress.md`, 초기 계획은 `resume-hard-task.md`.
**정상 동작 기준선은 이 문서(Plan A)** 다 — Plan B를 고쳤을 때 `[MITM/h2]`로 같은 `FILE UPLOAD DETECTED`가
떠야 성공.
