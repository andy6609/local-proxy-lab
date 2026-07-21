# proxy_beyond — 방향 & 결정 노트 (memory)

> `proxy_beyond/` 트랙(연구용 프록시)의 **문맥·결정 기억**을 모아두는 곳.
> 새 세션/다음 사람이 여기부터 읽으면 "왜 이렇게 가는지"를 안 흔들리고 잡을 수 있다.
> 프로토콜 커버리지 **기준 문서**는 `../docs/scope-and-protocol-coverage.md`. (여긴 요약 + 트랙 노트)
> 최종 갱신: 2026-07-13

---

## 1. 이 프로젝트가 뭔가 (성격)

- **Fasoo 인턴 연구 PoC.** 목표 = **AI 서비스(ChatGPT/Gemini/네이버 등) 파일 업로드를 MITM 프록시로 식별.**
- 배경: Fasoo **DRM**(문서 암호화 제품)/**Wrapsody** 맥락. "파일이 네트워크로 나갈 때 무엇이·어떤 등급/라벨로
  나가는지"를 프록시로 관측·차단 가능한지 검증. (DRM이 API hook 시 파일을 읽는지 vs 네트워크로 나가는지도 확인)
- **코드 성격 (중요):** 회사 제출·제품화 코드가 **아님.** 단, **이력서/포트폴리오로 공개할 코드**라
  학습용 최소 코드도 아니고 **견고하게(solid)** 간다.
- **이력서 핵심 = "파일 업로드를 식별해 (회사) 제품에 기능으로 추가했다."** TLS MITM·프로토콜 처리는 수단.
- 멘토님 1순위 = **"전체를 처음부터 끝까지 설명할 수 있다."**

### 견고함의 선 긋기
- **유지(이력서 값어치):** v4 수준 파서 견고성·에러처리·자원정리·로깅·문서화된 한계.
- **지양(풀 프로덕트/과잉):** WFP 커널통합, IOCP, fail-close 정책엔진, 분산 복호화 장비.

---

## 2. 코드 트랙 (어느 파일이 무엇인가)

새 기능은 **연구 트랙(v4 계열)에만** 얹는다.

| 파일 | 트랙 | 상태 |
|------|------|------|
| `proxy_MITM_pure/proxy_MITM_pure.cpp` | **학습용 최소판** | 개념 이해용. **그대로 둔다(기능 안 얹음).** |
| `proxy_v4/proxy_v4.cpp` | **연구 트랙 베이스** | 견고한 파서/인증서캐시+락/스머글링방어/타임아웃/keep-alive/구조화 로깅 |
| `proxy_beyond/proxy_plan_A.cpp` | **연구 트랙 · Plan A** | v4 기반. 2026-07-13 생성. **✅ 빌드+실행 검증됨.** (아래 §4) |
| `proxy_beyond/proxy_plan_B.cpp` | **연구 트랙 · Plan B** | nghttp2 h2 브릿지. 2026-07-13 생성. **빌드 미검증(nghttp2 미설치).** (아래 §4-B) |

> 주의: "제품처럼 하드닝"과 "이력서용 견고함"은 다른 축. 후자는 유지, 전자(WFP/IOCP)는 지양.

---

## 3. 프로토콜 커버리지 계획 (요약 — 상세는 scope 문서)

- **HTTP/1.1** — 됨(v4 파서).
- **HTTP/2** — **Plan A**(ALPN로 http/1.1 강제 다운그레이드, 지금) → **Plan B**(nghttp2로 실제 h2 파싱:
  프레이밍+HPACK+스트림 멀티플렉싱, 나중). Plan A break = **gRPC/h2-only 클라 → handshake 실패**.
- **HTTP/3(QUIC)** — **범위 안.** UDP+TLS1.3이라 TCP MITM으로 안 잡힘.
  - **C-1**(UDP:443 차단→TCP 폴백, 권장 우선) / **C-2**(ngtcp2·quiche + QPACK 실제 복호화, 본격 확장)
  - ★ **미결정:** C-1까지냐 C-2까지냐 → **멘토 확인 필요.**
- **WFP 커널/transparent redirect** — 지금 **제외**(시간). local 견고화 후. 현재는 explicit proxy
  (`curl -x`/브라우저 프록시설정)로 유도.

> 옛 문서들(`execution-plan-to-mitm.md`, `project-goal-and-roadmap.md`, `main_purpose.md §8.3`, `m4-notes.md (A)`)의
> "h2·QUIC 범위 밖" 서술은 `../docs/scope-and-protocol-coverage.md` 가 대체함(포인터 달아둠).

### 3.1 왜 Plan A(1.1로 강제) 먼저, Plan B(h2 파싱) 나중인가

1. **목표가 "파일 업로드 식별"이지 "h2 파싱"이 아니다.** Plan A 는 기존 HTTP/1.1 파서를 그대로 재사용해
   목표를 **지금 바로** 달성한다. B 부터 하면 h2 엔진(HPACK·멀티플렉싱)을 다 만들 때까지 **업로드를 하나도 못 잡는다.**
2. **식별 로직은 h2/1.1 동일.** 두 버전은 담는 정보(method·헤더·파일이름·body)가 같고 프레이밍만 다르다.
   → 쉬운 1.1 에서 식별 로직을 먼저 완성하고, B 에선 **앞단에 h2 디코더만 갈아끼운다.**
   Plan A 의 `scanMultipart`(업로드 식별)를 **Plan B 가 그대로 재사용** → A 작업은 안 버려진다.
3. **리스크 순서.** A = ALPN 2줄 + 기존 파서(작고 검증 쉬움, 이미 검증됨). B = h2 엔진 전체(라이브러리 + 콜백/
   멀티플렉싱 디버깅, 큼·위험). **싸고 확실한 것 먼저 → 파이프라인 증명 후 확장.**
4. **A 도 이미 실브라우저를 커버한다.** 크롬(h2 선호)도 ALPN 다운그레이드로 1.1 로 내려와 잡힌다.
   Plan B 가 필요한 건 **1.1 을 아예 거부하는 클라(gRPC/h2-only)** 때문 = **더 좁은 이유** → 나중이 맞다.

> 한 줄: **먼저 되게(A) → 그다음 넓히기(B).** A 산출물을 B 가 물려받으므로 A→B 가 자연스럽고 낭비가 없다.
> (Plan A 는 h2 를 "막는" 게 아니라 ALPN 에서 1.1 로 협상시켜 내리는 것 — 브라우저가 얌전히 따라옴.)

---

## 4. Plan A 구현 노트 (`proxy_beyond/proxy_plan_A.cpp`)

**proxy_v4 대비 더한 것 3가지:**
1. **ALPN로 h2→http/1.1 강제**
   - 세션1(브라우저↔프록시): `SSL_CTX_set_alpn_select_cb` → 무조건 `http/1.1` 선택 (`alpnSelectHttp11`)
   - 세션2(프록시↔서버): `SSL_set_alpn_protos` → `http/1.1`만 광고
2. **Fiddler급 트래픽 가시화** — 요청/응답 전체 헤더 덤프 (`SHOW_FULL_HEADERS`, `dumpRequestView`/`dumpResponseView`)
3. **파일 업로드 식별 시작(7주차 씨앗)** — `multipart/form-data` 감지 → boundary 추출 →
   요청 body 를 상한(`UPLOAD_CAPTURE_CAP=256KB`)까지 캡처하며 전달 → `scanMultipart` 로 part별
   `name`/`filename`/`Content-Type` 추출 → `*** FILE UPLOAD DETECTED` 로그.

**빌드 방법 (검증됨 2026-07-13):** proxy_v4 처럼 **VS 프로젝트가 아니라 cl.exe 커맨드라인**으로 빌드한다.
OpenSSL 은 vcpkg(`C:\vcpkg\installed\x64-windows`), MSVC 는 VS2022 vcvars64.
```
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
cd proxy_beyond
cl /nologo /EHsc /std:c++17 /utf-8 /I "C:\vcpkg\installed\x64-windows\include" proxy_plan_A.cpp ^
   /link /LIBPATH:"C:\vcpkg\installed\x64-windows\lib"
```
(lib 이름은 코드의 `#pragma comment(lib,...)` 가 지정 → include/lib 경로만 주면 됨)

**실행 준비:** exe 옆에 `rootCA.crt`/`rootCA.key` + OpenSSL DLL 3개(`libssl-3-x64.dll`, `libcrypto-3-x64.dll`,
`legacy.dll`) 필요 → `proxy_v4/` 에서 복사해둠. OS 신뢰 등록은 `../docs/m4-mitm-setup.md`.

**검증된 테스트 (둘 다 성공):**
```
curl.exe --ssl-no-revoke --cacert rootCA.crt -x http://127.0.0.1:18080 https://httpbin.org/get
curl.exe --ssl-no-revoke --cacert rootCA.crt -x http://127.0.0.1:18080 -F "file=@hello.txt" https://httpbin.org/post
```
→ 복호화 평문 헤더 덤프 + `*** FILE UPLOAD DETECTED ... filename="hello.txt" type="text/plain"` 확인됨.

**알려진 한계:**
- ALPN 다운그레이드는 h2-only 클라(gRPC)엔 안 통함 → 세션1 실패 (Plan B 에서 해소).
- 업로드 캡처는 상한까지만 → 큰 body 뒤쪽 part 놓칠 수 있음.
- **Content-Encoding(gzip/br) 압축 body 는 아직 해제 안 함** → 압축 본문 평문 스캔 불가 (다음 작업 후보).
- upstream 인증서 검증 `SSL_VERIFY_NONE`(PoC).

## 4-B. Plan B 구현 노트 (`proxy_beyond/proxy_plan_B.cpp`) — ★ 빌드 미검증

**Plan A 와의 차이:** ALPN 에서 h2 를 **그대로 협상** → **nghttp2 로 실제 h2 파싱.** h2 아닌 클라는
HTTP/1.1 경로로 자동 fallback(두 경로 다 지원).

**구조 = h2-to-h2 리버스 프록시:**
- `csess`(nghttp2 server, 브라우저측) ↔ `usess`(nghttp2 client, upstream측) 를 콜백으로 잇는다.
- HPACK 해제/프레이밍/흐름제어는 **nghttp2 담당**. 우리는 `on_header`/`on_data_chunk`/`on_frame_recv`
  로 헤더·DATA 를 받아 반대편 세션에 `submit_request`/`submit_response` + data provider 로 흘린다.
- I/O: 두 SSL 소켓을 **non-blocking + select** 로 멀티플렉싱(`runH2Bridge`).
- 업로드 식별: 요청 DATA(=`on_data_chunk`)를 `uploadCap` 에 캡처 → END_STREAM 시 `scanMultipart`.

**빌드 추가 요건:** OpenSSL + **nghttp2**(`vcpkg install nghttp2:x64-windows`), `#pragma comment(lib,"nghttp2.lib")`,
실행 시 `nghttp2.dll` 필요.

**미검증/한계:** nghttp2 콜백 흐름·select 루프·data provider resume 타이밍은 **실트래픽 디버깅 필요**;
h2↔1.1 **프로토콜 번역 미구현**(불일치 시 종료); H2Stream 은 브릿지 종료 시 일괄 free(장수명 연결 누적);
Content-Encoding 미해제; QUIC 은 Plan C(별개).

---

## 5. 이번 주 필수 (2026-07-13 주)

1. **Fiddler처럼 실제 트래픽 보이게** 코드 (→ Plan A §4-1,2 로 착수됨). 검증: **복호화가 Fiddler와 동일한가.**
2. **(비암호화 기준) 파일 업로드 식별 리서치** — AI 창 업로드 시 TCP 스트림/트래픽 모양 조사, 서비스별 업로드 지문표.

## 6. 열린 결정 (확인 필요)
- QUIC: C-1(차단→폴백)까지냐 C-2(실제 복호화)까지냐 — **멘토 확인.**
- 업로드 "100% 식별 가능한가" (TCP 분할로 단서 조각화) — 실제 캡처로 확인 후 파서 설계.
- (미팅 노트의 애매한 표현들) "암호화된 파일이니까 DRM은 어차피 이걸 못 염"의 정확한 의미, "각 CLI마다 local 프록시" 의도 — 멘토 재확인.
  - **2026-07-14 실험이 준 네트워크 층 의미:** DRM 보호 파일은 **네트워크에도 Fasoo 암호문 그대로** 나간다
    → 프록시는 업로드 이벤트·파일명·타입(메타데이터)은 잡되 **본문 내용은 못 읽음.** 반대로 예외 폴더의 평문 파일은 내용까지 읽힘. (§7 참조)
    → DLP 관점 앵글: "보호 안 된 **평문** 파일이 AI 서비스로 새는 것"을 식별하는 것이 프록시의 실질 값어치. (멘토 확인 시 이 관점 제시)

## 7. 개발 환경 결정 (2026-07-13 → **2026-07-14 갱신**)

- **결론: 호스트 Windows 에서 그대로 개발한다. Hyper-V clean VM 은 (DRM 회피 목적으론) 불필요.**
  - 원래 결정(2026-07-13)은 호스트에 **Fasoo DRM 이 깔려 파일이 투명 암호화**되니 개발/업로드 파일 검증(7~8주차)에
    마찰 → **clean VM 으로 우회**하려던 것이었다.
  - **2026-07-14 실험으로 우회 불필요 판명:** Fasoo **exception(예외) 폴더** 를 쓰면 호스트에서도 평문 파일을 얻는다.
    실제 브라우저(Edge) 업로드 → Plan A 프록시로 검증:
    - 예외 폴더에서 **새로 생성한** `.docx` → 네트워크로 `PK♥♦`(정상 ZIP/OOXML) **평문** 으로 나감 → 프록시가 내용까지 봄.
    - DRM 걸린 파일 → `...encrypted and protected by Fasoo DRM` **암호문** 으로 나감 → 프록시는 메타데이터만.
  - **주의(중요):** 예외 폴더는 **거기서 새로 만든 파일** 에만 적용된다. 이미 암호화된 파일을 예외 폴더로 **옮겨도
    복호화 안 됨**(암호문 유지, Content-Length 동일로 확인). → 평문 테스트가 필요하면 **예외 폴더 안에서 새로 만들거나
    "다른 이름으로 저장"** 할 것.
  - ⚠️ **검증 함정(2026-07-21 추가) — DRM은 프로세스 기반:** "이 파일이 평문인가"를 **git bash 등 Fasoo 허가 프로세스로 판단하면 안 된다.** 허가 프로세스는 DRM 파일도 **복호화된 평문**으로 보여준다. 실측: 예외폴더에 **DRM 문서를 복사**해 둔 파일이 git bash엔 평문(13699B)이었으나 **크롬 업로드는 DRM 암호문(19856B `DRMONE`)** 이었다(위 "옮기면 암호문 유지"와 일치). → **평문/DRM 판정은 반드시 프록시 캡처(=업로드 앱이 실제 보낸 바이트) 기준으로.** 상세: `../proxy_ToInfinity/docs/ai-upload-fingerprints.md`.
  - **macOS(개인 맥) 는 여전히 안 씀.** 코드가 Windows 네이티브(WinSock2 등)라 POSIX 포팅 필요 +
    **최종 타깃이 Windows(Fasoo/WFP)** + WFP 단계는 Windows 전용.
- **(참고) VM 이 여전히 쓸 만한 경우:** 완전 격리·재현 환경이 필요하거나 DRM 정책과 무관한 깨끗한 상태를 원할 때. **필수는 아님.**
- **VM 을 굳이 쓸 때의 세팅 체크리스트 (검증된 호스트 빌드와 동일 재현):**
  1. Hyper-V 에 Windows 10/11 VM
  2. Git, **VS2022**(또는 MSVC Build Tools = cl.exe), **vcpkg** 설치
  3. `vcpkg install openssl:x64-windows nghttp2:x64-windows` (nghttp2 는 Plan B 용)
  4. `git clone https://github.com/andy6609/local-proxy-lab.git`
  5. rootCA 생성(openssl CLI, `../docs/m4-mitm-setup.md`) + `certutil -addstore -user Root rootCA.crt`
  6. 빌드: §4 의 cl.exe 커맨드. 실행 시 OpenSSL(+nghttp2) DLL 을 exe 옆에.
