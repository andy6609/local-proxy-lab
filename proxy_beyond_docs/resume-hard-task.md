# Hard Task — Plan B h2 응답 경로 디버깅 (response re-encode / resume)

> **한 줄:** `proxy_plan_B.cpp` 는 h2 **복호화·요청 방향은 되는데**, upstream 응답을 브라우저로
> **h2 로 재조립해 되돌려주는 방향이 깨져** `ERR_HTTP2_PROTOCOL_ERROR` 가 난다. 이걸 고치는 게
> **Plan B(진짜 h2 프록시) 완성의 마지막 관문**이다.
>
> 배경/전체 결과: `windows-run-guide.md` §6.6(계획)·§6.7(실제 결과). 이 파일은 그 §6.7 의 "다음 디버깅 지점"을 깊게 판 것.
> 최초 작성: 2026-07-15.

---

## 1. 증상 (정확히)

프록시 물린 격리 브라우저로 claude.ai 접속 시 `proxyB.log`:
```
MITM/h2 claude.ai bridge established (decrypting h2)   ← ✅ h2 복호화 성공
===== [MITM/h2] >> REQUEST  GET claude.ai/ =====       ← ✅ 요청 헤더까지 디코드
   (…이 요청에 대한  << RESPONSE claude.ai/  가 로그에 없음)   ← ❌ 응답이 안 나감
```
- 브라우저: `ERR_HTTP2_PROTOCOL_ERROR` → 페이지 **백지**.
- **부분 성공 단서:** 같은 세션에서 `nav-edge.smartscreen…` 의 **작은 응답(400)** 은 브라우저로 **정상 전달됨**.
  → 응답 경로가 완전히 죽은 게 아니라 **큰/스트리밍 응답에서만** 깨진다. (이 비대칭이 핵심 힌트)

## 2. 재현 절차

1. `proxy_plan_B.exe` 실행 (nghttp2.dll 옆에).
2. 프록시 물린 **격리** 브라우저로 claude.ai:
   `msedge.exe --user-data-dir=<temp> --proxy-server=127.0.0.1:18080 https://claude.ai`
   (⚠️ 반드시 이 창에서. 평소 브라우저는 프록시 안 탐 — §6.7 함정 참조.)
3. `proxyB.log` 를 `bridge established` 부터 확인 → `<< RESPONSE claude.ai/` 가 **없는지** 확인.
4. **대조군:** 작은 응답 사이트(예: `https://httpbin.org/get`)로도 접속 → 거긴 `<< RESPONSE` 가
   정상으로 나오는지 확인해 "작은 건 되고 큰 건 안 된다"의 경계를 고정.

## 3. 코드 지도 (`proxy_plan_B.cpp`)

응답 흐름: **upstream(`usess`) 수신 → `H2Stream` 에 모음 → 클라(`csess`)로 `submit_response` + `respBodyRead` data provider → `runH2Bridge` select 루프가 두 세션 IO 를 굴림.**

| 함수 / 심볼 | 줄 | 역할 |
|---|---|---|
| `respBodyRead` | 685 | **클라로 나갈 응답 body 를 h2 DATA 로 내보내는 data provider.** DEFERRED 반환/EOF 플래그 타이밍이 핵심 |
| `reqBodyRead` | 671 | (참고) 요청 body → upstream 방향. 이건 잘 됨 |
| `cb_on_header` | 746 | 헤더 수신 → `H2Stream::reqHdr/respHdr` 채움 |
| `cb_on_frame_recv` | 772 | 헤더 END / DATA END_STREAM 시 `submit_*` 트리거 + `resume`. 응답측 `respEof` 세팅(807) |
| `cb_on_data_chunk` | 812 | upstream 응답 DATA 를 `respBody` 에 append + `nghttp2_session_resume_data(csess, cid)` (822/827) |
| `nghttp2_submit_response` | 727 | 클라 세션에 응답 제출 |
| `nghttp2_session_resume_data` | 791·807·822·827 | DEFERRED 된 data provider 재개 |
| `runH2Bridge` | 890 | 두 SSL 논블로킹 + select 멀티플렉싱 |
| `H2Stream` / `H2Bridge` | 618·644 | 스트림 상태(cid/uid, respHdr/respBody, respEof 등) |

## 4. 가설 (우선순위)

1. **data provider resume 타이밍 / DEFERRED (1순위)**
   `respBodyRead` 가 아직 보낼 데이터가 없으면 `NGHTTP2_ERR_DEFERRED` 를 반환하고 멈춘다. upstream DATA 가
   더 도착하면 `nghttp2_session_resume_data(csess, cid)` 가 **정확히** 불려야 다시 `respBodyRead` 가 호출된다.
   **큰 응답 = 여러 DATA 청크**라, 첫 청크 후 DEFERRED → resume 누락/순서꼬임이면 거기서 stall. 작은 응답(1청크로 끝)은
   DEFERRED 없이 끝나서 되는 것과 **정확히 일치**. → **여길 제일 먼저 본다.**
2. **flow control (WINDOW_UPDATE)**
   큰 body 는 흐름제어 윈도우 단위로 쪼개 보내야 함. 윈도우 소진 후 재개 로직이 없으면 **큰 응답만** 멈춤 → 증상 일치.
3. **응답 헤더 번역**
   h2 는 hop-by-hop 헤더(`Connection`/`Keep-Alive`/`Transfer-Encoding`/`Upgrade`) **금지**. upstream 의 1.1식/금지
   헤더를 그대로 `submit_response` 하면 프로토콜 에러. `:status` 필수. — 단 **작은 응답은 되므로** 헤더 자체보단
   body 스트리밍 쪽 의심이 크다(헤더면 작은 것도 깨져야 함).
4. **END_STREAM / `respEof` 타이밍**
   응답 끝 플래그를 너무 일찍(자름) 또는 늦게(안 끝남) 세팅.

## 5. 디버깅 순서

1. `respBodyRead` 에 로그 추가: **호출마다** `(반환값/length, *data_flags, DEFERRED 여부, respBody 남은 바이트, respEof)`.
2. `cb_on_data_chunk`·`cb_on_frame_recv` 의 `resume` 호출에도 로그 → **upstream DATA 도착 ↔ resume ↔ `respBodyRead` 재호출** 체인이 이어지는지 추적.
3. **작은 응답(1 DATA) vs 큰 응답(여러 DATA)** 로그를 나란히 비교 → 체인이 **어디서 끊기는지** 특정.
4. 끊기는 지점이:
   - "DEFERRED 반환 후 resume 안 옴" → **가설 1** (resume 배선/조건).
   - "resume 은 오는데 곧 다시 멈춤" → **가설 2** (flow-control 윈도우).
5. 헤더 의심 시: `submit_response` **직전에** hop-by-hop 헤더를 제거하는지 확인.

## 6. 성공 기준

- `proxyB.log` 에 `<< RESPONSE claude.ai/` 가 뜨고 **브라우저에 페이지 렌더.**
- 이어서 파일 업로드 시 `*** FILE UPLOAD DETECTED [MITM/h2] ... filename="..."`.
  (요청 방향 탐지는 **이미 됨** — 페이지만 뜨면 바로 잡힐 것.)

## 7. 왜 hard 인가

nghttp2 **비동기 콜백 + 자체 select 루프 + 흐름제어**가 얽혀, "established 떴는데 응답 안 옴"류는
재현·추적이 까다롭다. Plan B 는 원래 **미검증 배선**이라 이 부분이 처음으로 실트래픽에 노출된 지점.

## 8. 참고
- 전체 맥락·결과: `windows-run-guide.md` §6.6, §6.7 / 트랙 노트: `README.md`.
- **Windows 전용**(WinSock). 맥에서 재현하려면 포팅 필요(§7 개발환경 결정).
- 급하면 실사용/시연은 **Plan A**(1.1 다운그레이드, 응답까지 정상)로. Plan B 는 "진짜 h2" 값어치를 위한 확장.
