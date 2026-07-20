# M3 노트 — M2 대비 변화 + 어디까지 깊게 볼지

> 목적: M3(proxy_v3)는 "제품 수준 + 보안회사 제출" 기준.
> 하지만 내 진짜 목표는 **파일 업로드 탐지(M6~M7)**.
> 그 관점에서 "꼭 이해할 것 / 그냥 넘어갈 것(오버 구현)"을 구분해 둔다.
> (M1 한계 → `m1-tradeoffs.md`, M2 변화 → `m2-notes.md`)

---

## 1. M3 한 줄 요약

**M3 = HTTPS를 프록시로 통과시키는 단계.** 단, 내용은 못 본다(raw 통과).
- 평문 HTTP(GET/POST) → M2 파싱 루프
- HTTPS(CONNECT) → "200 Connection Established" 후 **blind 양방향 터널**

proxy_v3 = **M2 전부 + CONNECT 처리**. 이제 브라우저 프록시 설정하면
http/https 둘 다 경유된다.

---

## 2. M2 → M3 무엇이 달라졌나

| 항목 | M2 (proxy_v2) | M3 (proxy_v3) |
|---|---|---|
| 처리 메서드 | GET/POST 등 평문 HTTP만 | + **CONNECT (HTTPS 터널)** |
| HTTPS | 미지원(501 거부) | ✅ raw 터널로 통과 |
| blind relay | 안 씀 (M2에서 보류) | **CONNECT 전용으로 부활** (TunnelRelay) |
| 보안 추가 | - | **CONNECT 포트 화이트리스트**(443만 허용) |

### blind relay 가 왜 여기서 부활하나 (핵심)
- M2 에서 blind relay 를 "버린 게 아니라 CONNECT 전용으로 보류"라고 했었다.
- HTTPS 는 CONNECT 직후부터 **TLS 암호 바이트**가 흐른다.
- 프록시는 이걸 **복호화 못 한다(=내용 못 봄)** → 파싱이 불가능/무의미.
- 그래서 파싱하지 않고 그냥 양방향으로 흘려보낸다 = **blind relay** (M1 과 같은 구조).
- 즉 "파싱(M2) vs 통과(M1)"는 상황에 따라 둘 다 필요했던 것:
  - 평문이면 파싱, 암호면 통과.

---

## 3. ★ 꼭 이해하고 갈 메인 로직

### (A) CONNECT 흐름 — `HandleConnect`
```
브라우저 -> 프록시 : "CONNECT example.com:443 HTTP/1.1"
프록시   -> 서버   : TCP connect(example.com:443)
프록시   -> 브라우저: "HTTP/1.1 200 Connection Established"
--- 이후 ---
브라우저 <-> 프록시 <-> 서버 : 암호 바이트 양방향 통과
```
- `CONNECT` 는 **HTTP 메서드**다(GET/POST 처럼). "터널 뚫어줘"라는 요청.
- TCP 3-way 와 다른 레이어. CONNECT 는 그 위(HTTP)에서 하는 터널 협상.

### (B) pre-read 함정 — `takeBuffered()`
- **이게 M3에서 제일 미묘하고 중요한 부분.**
- M2 의 SockReader 는 효율을 위해 한 번에 많이 읽는다(over-read).
  CONNECT 줄을 읽다가 그 뒤(=TLS ClientHello 시작)까지 버퍼에 들어와 있을 수 있다.
- 터널 시작 전에 이 잉여 바이트를 upstream 으로 **먼저 보내야** 한다.
  안 보내면 ClientHello 앞부분이 사라져서 **TLS handshake 가 깨진다.**
- → `takeBuffered()` 로 꺼내 upstream 에 흘려보낸 뒤 blind relay 시작.

### (C) 양방향 blind 터널 — `TunnelRelay`
- M1 의 Relay 와 동일 구조: `recv(from) -> send(to)` 루프, 끝나면 `shutdown(SD_SEND)`.
- 스레드 2개로 양방향 동시. 한쪽 끊기면 shutdown 으로 반대쪽도 종료.
- (M1 을 제대로 이해했으면 여기는 복습 수준)

---

## 4. 🟡 오버 구현된 부분 (개념만 알고 넘어감)

| 부분 | 위치 | 왜 오버인가 | 어느 수준까지 |
|---|---|---|---|
| CONNECT 포트 화이트리스트 | `isConnectPortAllowed` | 보안 가산점(SSRF/포트스캔 방지)이지 탐지와 무관 | "아무 포트나 못 뚫게 막는다" 개념만 |
| 터널 바이트 카운트 로깅 | `TunnelRelay` 의 atomic counter | 관측용 부가기능 | 거의 안 봐도 됨 |
| recv 타임아웃/SO_REUSEADDR | M2 승계 | 운영 안정성 | 개념만 |
| M2 의 오버 부분 전부 | (m2-notes.md 참고) | 동일 | 동일 |

> 참고: CONNECT 포트 제한은 "보안회사 제출"이라 넣은 것.
> 순수 학습/탐지만 보면 빼도 동작에는 지장 없음.

---

## 5. 이 단계가 파일 업로드 탐지와 어떻게 이어지나 (중요)

- **M3 까지는 HTTPS 내용을 못 본다.** 터널로 그냥 통과만 시킨다.
- 근데 ChatGPT/Gemini 등은 전부 **HTTPS**다. 즉 지금 상태로는
  파일 업로드를 봐도 **암호화돼서 아무것도 못 본다.**
- 그래서 다음 단계 **M4~M5(TLS MITM)** 가 필수:
  - 프록시가 CONNECT 를 받으면 "그냥 통과(M3)"가 아니라
    **내가 직접 TLS 를 끊어서(=가짜 인증서로 클라와 handshake)** 복호화한다.
  - 그러면 비로소 평문 HTTP 가 나오고 → M2 파서로 분석 → M6~M7 업로드 탐지 가능.
- 즉 **M3 의 CONNECT 처리 위치(HandleConnect)가 M4 에서 MITM 이 끼어들 자리**다.

```
M3: CONNECT -> [그냥 blind 통과]
M4: CONNECT -> [내가 TLS 끊고 복호화] -> 평문 -> M2 파서 -> (M6 탐지)
```

---

## 6. 테스트 방법 (요약)

프록시 실행 후:
```powershell
# HTTP (M2 경로 그대로 동작)
curl.exe -x http://127.0.0.1:18080 http://httpbin.org/get

# HTTPS (M3 CONNECT 터널) -> 정상 페이지 + 콘솔에 "tunnel open/closed" 로그
curl.exe -x http://127.0.0.1:18080 https://httpbin.org/get

# 포트 화이트리스트 거부 (443 외 포트) -> 403
curl.exe -x http://127.0.0.1:18080 https://httpbin.org:8443/
```
> 단, HTTPS 라도 **내용은 여전히 못 본다**(raw 통과). 페이지가 뜨는 것 = 터널 성공.

---

## 관련 문서
- 실행 계획: `execution-plan-to-mitm.md` (M3 정의)
- 이전 단계: `m1-tradeoffs.md`, `m2-notes.md`
- 코드: `../proxy_v3/proxy_v3.cpp` (맨 아래 "M3의 알려진 한계" 주석)
