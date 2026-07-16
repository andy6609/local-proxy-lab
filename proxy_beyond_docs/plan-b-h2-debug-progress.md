# Plan B h2 디버깅 진행 기록 (2026-07-16)

> `proxy_plan_B.cpp`(진짜 HTTP/2 프록시) 디버깅 중간 스냅샷. "문제가 뭔지 + 여태 어떻게 좁혀왔는지".
> 관련: `resume-hard-task.md`(초기 가설), `windows-run-guide.md` §6.6/§6.7.

---

## 1. 문제 (증상)

Plan B 프록시에 브라우저를 붙이면 **거의 모든 h2 사이트가 안 뜬다** → `ERR_HTTP2_PROTOCOL_ERROR`, 페이지 백지.
claude.ai뿐 아니라 wikipedia 등도 동일. (그래서 시스템 프록시로 전역 적용 시 브라우징 전멸.)

## 2. 핵심 진단 — 처음 생각과 뒤집힘 ⚠️

- **처음 가설:** "응답을 브라우저로 h2 재조립하는 부분(respBodyRead/resume)이 깨진다." (resume-hard-task.md)
- **계측으로 밝혀진 실제:** 그 단계까지 가지도 못한다. **upstream 서버가 우리가 전달한 요청 스트림을
  즉시 `RST_STREAM` 으로 끊는다.** → 응답이 아예 안 온다 → 우리가 브라우저 스트림도 RST → 브라우저 `ERR_HTTP2_PROTOCOL_ERROR`.
- **RST 에러코드 = 1 (PROTOCOL_ERROR).** 서버가 "이 요청은 h2 프로토콜 위반"이라 판단.
- **결정적:** claude.ai(Cloudflare)**와** wikipedia(non-Cloudflare) **둘 다 동일하게 RST err=1.**
  → 특정 서버/CF 문제가 아니라 **우리가 만든 upstream 요청 자체가 잘못됐다.**
- **대비 단서:** 작은 **POST**(smartscreen)는 `<< RESPONSE (400)` 응답이 옴. 실패한 건 **GET(무-body)** 요청들.
  → **무-body(GET) 요청 형성에 버그**가 있을 가능성이 높다. (아직 최종 확정 전)

즉 한 줄: **"응답 재조립 이전에, 우리가 보낸 요청을 서버가 프로토콜 위반으로 거절한다."**

## 3. 여태 한 것 (시간순)

1. **Plan B 첫 컴파일 성공** (그동안 미검증):
   - MSVC엔 `ssize_t` 없음 → nghttp2.h가 C2065 → include 전에 `typedef SSIZE_T ssize_t;` 추가.
   - `dumpHeadView` 인자 `const char*` → `const std::string&` (C2664).
2. **응답 경로 계측 삽입**(임시, `g_dbgH2`/`dbgHost`로 대상 호스트만): `respBodyRead`, `submitClientResponse`,
   `cb_on_frame_recv`의 프레임 타입/`RST err`/`GOAWAY err`, `submitUpstreamRequest`의 pseudo-header + 전달 헤더,
   `pumpRecv`의 소켓 수신 바이트.
3. **관측 결과로 원인 이동:** 요청은 나가는데(`>> REQUEST GET ...` + submit 성공) upstream이 `type=3(RST) err=1`로 즉시 끊음.
   응답 콜백(`upstream HEADERS`/`respBodyRead`)은 **한 번도 안 불림.**
4. **서버 무관 확인:** wikipedia도 동일 RST err=1 → 우리 요청 형성 문제로 범위 축소.

## 4. 지금 가설 & 다음 스텝

**가설:** 무-body(GET) 요청을 `nghttp2_submit_request(..., data_prd=nullptr)`로 보낼 때, 전달 헤더 중 무언가가
strict h2 서버가 거부하는 위반이다. 후보:
- 전달 헤더 중 하나(예: `upgrade-insecure-requests`, `priority`, `sec-fetch-*` 등 — 실제론 정상이어야 하지만 bisect 필요)
- pseudo-header 처리(`:path`/`:authority`) 또는 END_STREAM/data-provider 처리의 미묘한 문제

**다음 스텝:**
1. 전달 헤더를 **최소셋(:method/:scheme/:path/:authority + accept 정도)**으로 줄여 GET을 보내 RST가 사라지는지 → bisect로 범인 헤더 특정.
2. 헤더가 아니면 `nghttp2_submit_request` 무-body 경로(END_STREAM 플래그)와 세션 SETTINGS/flow-control 점검.
3. 요청이 통과되면 **그때** 원래 의심했던 응답 재조립(resume-hard-task.md)을 검증.

## 5. 상태 메모
- Plan B 코드에 **디버그 계측이 아직 들어있음**(`g_dbgH2=true`, `dbgHost`). 원인 잡고 나면 제거.
- 실사용/시연은 여전히 Plan A(1.1 다운그레이드)로 가능(응답까지 정상).
- Windows 전용(WinSock). 재현은 프록시 물린 격리 브라우저 또는 시스템 프록시(Fiddler 끄고)로.
