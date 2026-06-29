# 프록시 구조 설명서 — HTTP 처리

> **용도:** 팀 공유용. 우리 프록시가 어떤 구조로 흐르는지 설명 위주로 정리.
> **범위:** HTTPS 복호화(MITM) 이전 = HTTP/HTTPS 터널을 다루는 부분.
> **코드:** `proxy_arch/proxy_arch.cpp`

---

## 0. 한 줄 정의

**포워딩 프록시 = 클라이언트(브라우저)와 진짜 서버 사이에 끼어,
클라의 요청을 대신 서버에 전달하고 응답을 되돌려주는 중계자.**

```
브라우저  ──요청──▶  [프록시]  ──요청──▶  진짜 서버
브라우저  ◀──응답──  [프록시]  ◀──응답──  진짜 서버
```

---

## 1. 연결 흐름

```
main()
  └── RunServer()               listen 소켓 + accept 루프 + 연결당 스레드

         accept() 새 소켓
           └── HandleClient()  첫 줄 읽어서 CONNECT vs HTTP 분기
                 ├── HandleConnect()   HTTPS 터널
                 │     ConnectUpstream(:443)
                 │     → "200 Connection Established"
                 │     → Relay ×2 (양방향)   ← ★ MITM 끼어들 자리
                 │
                 └── HandleHttp()      평문 HTTP 파싱 루프
                       SockReader      TCP 스트림 버퍼드 리더
                       readHead()      시작줄 + 헤더들 파싱
                       BodyMode 판정   Content-Length / chunked / 없음
                       [요청 전달 → 응답 받기 → body 전달] 반복
```

---

## 2. 공통 골격 — 모든 포워딩 프록시가 갖는 구조

단계나 구현체가 달라도 바깥 골격은 같다. 가운데 "연결 처리"만 바뀐다.

### (a) 서버를 세운다

```
WSAStartup            Windows 소켓 라이브러리 초기화
  └ socket()          듣기용 소켓 1개 생성
     └ bind(:18080)   "이 포트로 들어오는 연결을 내가 받는다"
        └ listen()    연결 대기 상태로 전환
           └ accept() 연결 하나 들어올 때마다 새 소켓 반환 → 반복
```

`accept()` 가 반환하는 건 연결 하나당 새 소켓. listen 소켓은 계속 다음 연결을 받는다.

### (b) 연결마다 동시 처리

연결이 여러 개 동시에 들어오므로 각 연결을 별도 스레드로 처리한다.

```
accept() → std::thread(HandleClient, 새 소켓).detach()
```

> **우리 구현 vs 실제 고성능 프록시의 차이는 §4 참고.**

### (c) 진짜 서버로 연결 — ConnectUpstream

```
getaddrinfo(도메인, 포트)   도메인 이름 → IP 주소 변환 (DNS 조회)
  └ socket()               서버로 나갈 소켓 생성
     └ connect()           그 IP:포트로 TCP 연결
        └ freeaddrinfo()   조회 결과 메모리 해제
```

`getaddrinfo` 는 OS API. 한 도메인에 IP 가 여러 개일 수 있어 목록으로 돌려준다.

### (d) 데이터를 옮긴다

- `recv()` — 소켓에서 바이트를 받는다. 받을 게 없으면 블록(대기).
- `send()` — 소켓으로 바이트를 보낸다. 한 번에 다 안 나갈 수 있어 `sendAll` 로 반복.
- `shutdown(SD_SEND)` — "나는 더 안 보낸다" 신호 → 반대쪽이 `recv` 0 을 받아 같이 종료.
- `closesocket()` — 소켓 정리.

---

## 3. 연결 처리 두 갈래

### (a) 평문 HTTP — HandleHttp

브라우저가 `GET http://example.com/` 같은 요청을 보낼 때.

**파싱 루프 흐름:**
```
반복 {
  ① 요청 헤드 파싱   시작줄(method/URL/version) + 헤더들
  ② upstream 연결
  ③ 요청 헤드 + body 를 upstream 으로 전달
  ④ 응답 헤드 파싱   status code
  ⑤ 응답 헤드 + body 를 브라우저로 전달
  ⑥ keep-alive 면 반복, 아니면 종료
}
```

**왜 "파싱 루프"가 필요한가:**
TCP 는 스트림이라 `recv` 한 번에 HTTP 메시지가 딱 안 끊긴다.
- 헤더가 쪼개져 오거나 (부분 수신)
- 다음 요청 바이트까지 미리 읽혀버리거나 (over-read)

그래서 `SockReader` — "줄 단위 읽기 / N바이트 정확히 읽기 / 잉여 보관" 리더가 필요하다.

**body 경계 판정 (BodyMode):**

| 방식 | 판단 헤더 | 처리 |
|---|---|---|
| Content-Length | `Content-Length: N` | 정확히 N 바이트 읽음 |
| chunked | `Transfer-Encoding: chunked` | 청크 크기(16진수)별로 끊어 읽음 |
| 없음 | (둘 다 없음) | 응답: 연결 종료까지 / 요청: body 없음 |

body 경계를 알아야 keep-alive(같은 연결에서 다음 요청 이어받기)가 가능하고,
body 를 정확히 추출할 수 있다 — 파일 업로드 탐지의 직접 토대.

### (b) HTTPS 터널 — HandleConnect

브라우저가 `CONNECT example.com:443 HTTP/1.1` 을 보낼 때.

```
① upstream(:443) TCP 연결
② 브라우저에 "HTTP/1.1 200 Connection Established" 응답
   ↑ 터널이 열리는 순간
③ 양방향 Relay — 암호 바이트를 그대로 통과 (내용 못 봄)
```

**Relay 가 왜 스레드 2개인가:**
한 방향 `recv` 가 블록된 동안 반대 방향도 동시에 흘러야 한다(full-duplex).
스레드 1개면 한쪽 `recv` 에 갇혀 반대쪽이 멈춘다.

```
std::thread t(Relay, clientSock, upstream);  // 브라우저 → 서버
Relay(upstream, clientSock);                  // 서버 → 브라우저 (현재 스레드)
t.join();
```

CONNECT 는 HTTP 메서드지만 "TCP 터널을 뚫어달라"는 요청이다.
터널이 열린 뒤 프록시는 암호문만 보고, 브라우저와 서버가 직접 TLS 핸드셰이크를 한다.
→ **★ MITM 은 이 터널이 열리는 순간에 끼어드는 것이다.**

---

## 4. 실제 고성능 프록시와의 차이

우리 코드의 HTTP 처리 로직(파싱·CONNECT·릴레이)은 실제 프록시와 동일하다.
단, 다음 두 가지는 구현을 단순화한 부분이다.

### (A) I/O 동시성 모델

| | 우리 코드 | 실제 고성능 프록시 |
|---|---|---|
| 소켓 | blocking | non-blocking |
| 동시성 | 연결당 스레드 1개 | 이벤트 루프 (epoll / IOCP) + CPU 코어 수 스레드 |
| 한계 | 연결 N개 = 스레드 N개 → context switch 폭증 | 소수 스레드가 수만 연결 처리 |

### (B) 제품 수준 하드닝 (우리 코드에서 생략한 것들)

- 타임아웃 (느린/멈춘 연결 끊기)
- 헤더 크기 상한 (메모리 고갈 방어)
- Request Smuggling 방어 (`Content-Length` + `Transfer-Encoding` 동시 거부)
- upstream 커넥션 풀 (매 요청 새 연결 대신 재사용)
- HTTP/2, HTTP/3 지원 (우리는 HTTP/1.1 텍스트만)
- 구조화 로깅 / 에러 처리

---

## 5. 핵심 API 한눈에

| 구간 | API | 역할 |
|---|---|---|
| 서버 수립 | `WSAStartup` `socket` `bind` `listen` `accept` | listen 소켓 + 연결 수락 |
| 동시성 | `std::thread` + `detach` | 연결당 처리 |
| upstream | `getaddrinfo` `socket` `connect` `freeaddrinfo` | 도메인→IP, 서버 연결 |
| 데이터 | `recv` `send` `shutdown` `closesocket` | 바이트 송수신·정리 |
| HTTP 파싱 | `SockReader` `readHead` `BodyMode` | 스트림 읽기·body 경계 |
| HTTPS 터널 | CONNECT 분기 → `Relay` ×2 | 암호 바이트 통과 |
