# HTTP 프로토콜 실전 처리 — Keep-Alive · ALPN/HTTP2 · Chunked · Content-Encoding

> 커리큘럼 6~9번을 다룬다. 각 항목마다 **① 개념(왜·무엇을) 자세히 → ② 우리 코드(Plan A / Plan B)에서 어떻게** 순서로 정리했다.
> 코드: `proxy_beyond/proxy_plan_A.cpp`(h2를 1.1로 다운그레이드, 검증됨), `proxy_beyond/proxy_plan_B.cpp`(nghttp2로 실제 h2, 미검증).
> 사전 개념: HTTP 파싱은 4주차, TLS/ALPN 기초는 `docs/week5-tls-concepts.md`.

**한눈 요약**

| 항목 | Plan A | Plan B | 핵심 |
|---|---|---|---|
| 6. Keep-Alive 경계 구분 | ✅ | ✅ | body 끝을 알아야 다음 요청을 읽는다 |
| 7. HTTP/2 여부 + ALPN 제어 | ✅ (1.1 강제) | ✅ (h2 협상+분기) | 프록시가 협상 프로토콜을 정한다 |
| 8. Chunked Transfer Encoding | ✅ | ✅ (1.1 경로만) | 크기 모를 때 조각조각. h2엔 없음 |
| 9. Content-Encoding 압축 해제 | ❌ | ❌ | gzip/br 해제 미구현(공통 한계) |

---

## 6. HTTP/1.1 Keep-Alive 환경에서 요청/응답 경계 구분

### ① 개념

**Keep-Alive가 왜 생겼나.**
HTTP/1.0은 "요청 하나 → 응답 하나 → 연결 종료"였다. 페이지 하나에 이미지·CSS·JS가 수십 개면, 그때마다 TCP 3-way handshake + TLS handshake를 새로 하느라 느리고 낭비가 컸다. HTTP/1.1은 **하나의 TCP(+TLS) 연결을 재사용해 여러 요청/응답을 연속으로** 주고받는다. 이것이 Keep-Alive(지속 연결)다.

**Keep-Alive가 만든 문제 = 경계.**
한 연결에 요청과 응답이 줄줄이 흐르는데, **TCP는 바이트 스트림이라 "메시지 경계"라는 개념이 없다.** 그냥 바이트가 이어서 올 뿐이다. 그래서 받는 쪽은 스스로 **"이 요청(또는 응답)이 어디서 끝나고, 다음 것이 어디서 시작하는가"를 판정**해야 한다. 이 판정의 정확성이 Keep-Alive의 전부다.

**경계 판정 = body가 어디서 끝나는지 아는 것.**
시작줄과 헤더는 "빈 줄(`\r\n\r\n`)"로 끝나므로 경계가 명확하다(4주차). 문제는 body다. body의 끝을 아는 방법은 딱 세 가지뿐이다:

1. **`Content-Length: N`** → 빈 줄 이후 정확히 N바이트가 body. N바이트를 다 읽으면 끝.
2. **`Transfer-Encoding: chunked`** → 크기(16진수) 붙은 조각들이 오다가 "크기 0" 조각에서 끝(8번 항목).
3. **둘 다 없음** → 응답이면 "연결이 끊길 때까지"가 body(그래서 서버가 `Connection: close`), 요청이면 "body 없음".

body의 끝을 정확히 집어야 그 다음 바이트부터를 **다음 요청의 시작**으로 읽을 수 있다.

**경계를 틀리면 무슨 일이 나나.**
- **덜 읽으면**: body의 뒷부분이 남아서, 그게 "다음 요청"으로 오인된다 → 파싱이 어긋나 무너진다.
- **더 읽으면**: 다음 요청의 앞부분을 이번 body로 먹어버린다.
- 이 어긋남을 악용하는 게 **HTTP Request Smuggling**이다(4주차). 그래서 `Content-Length`와 `Transfer-Encoding`이 **동시에** 오면 프록시와 서버가 경계를 다르게 볼 수 있어 위험하다 → 거부해야 한다.

**언제 연결을 닫나.**
경계를 잘 넘겨 한 왕복을 끝냈어도, 언제까지 이 연결을 재사용할지 알아야 한다. `Connection: close` 헤더가 있거나, 프로토콜이 HTTP/1.0이면 이번 왕복 후 닫는다. 그 외에는 계속 재사용(루프).

### ② Plan A / Plan B 코드

두 파일 모두 동일한 구조다(Plan B의 1.1 fallback 경로가 Plan A와 같은 로직).

**(1) body 끝 판정 = BodyMode.**
`enum class BodyMode { None, Length, Chunked, UntilClose, Error };`
`requestBodyMode()` / `responseBodyMode()`가 헤더를 보고 위 4가지 중 하나로 판정한다.
```cpp
// 요청: Content-Length? chunked? 아무것도 없으면 body 없음
if (hasCL && hasTE) { err = "CL+TE smuggling"; return BodyMode::Error; }   // ★ 경계 모호 → 거부
if (hasTE) { ... return BodyMode::Chunked; }
if (hasCL) { clen = cl; return BodyMode::Length; }
return BodyMode::None;
```
응답은 여기에 `UntilClose`(연결 끊길 때까지)가 추가된다 — 요청엔 없다(요청은 끝을 명시해야 하므로).

**(2) 판정대로 정확히 body를 넘기기.**
`forwardExact(N, ...)`(Length), `forwardChunked(...)`(Chunked), `forwardUntilClose(...)`(UntilClose). 이 함수들이 "딱 그만큼"만 소비하기 때문에, 그 다음 바이트가 다음 요청의 시작으로 정확히 남는다.

**(3) 다음 요청을 또 읽는 Keep-Alive 루프.**
Plan A는 `proxyExchange()`, Plan B의 1.1 경로는 `proxyExchange11()`이 "요청 1개 + 응답 1개"를 처리하고, 그걸 `while(true)`로 반복한다:
```cpp
while (true) {
    bool closeAfter = false;
    if (!proxyExchange11("MITM/1.1", cReader, &cStream, uReader, &uStream, host, closeAfter)) break;
    if (closeAfter) break;   // ★ 여기서 연결 재사용 여부 결정
}
```

**(4) 언제 닫나 = closeAfter.**
```cpp
closeAfter = serverClosed || wantsClose(req, version) || wantsClose(resp, respVer);
```
`wantsClose()`는 `Connection: close`가 있거나 `HTTP/1.0`이면 true. `serverClosed`는 응답이 UntilClose로 끝난 경우(서버가 연결을 끊음).

> **정리:** BodyMode로 "body가 어디서 끝나는지" 판정 → forward*로 그만큼만 소비 → 남은 바이트를 다음 요청으로 → closeAfter가 false인 한 루프. 이것이 Keep-Alive 경계 구분의 전부다. (Plan B의 **h2 경로**는 이 문제가 아예 없다 — h2는 스트림 ID로 메시지를 구분하므로 경계를 nghttp2가 관리한다. 6번은 순수 1.1 이슈다.)

---

## 7. HTTP/2 사용 여부와 ALPN 제어

### ① 개념

**ALPN 복습(5주차).**
ALPN(Application-Layer Protocol Negotiation)은 TLS handshake 중에 "이 연결에서 어떤 상위 프로토콜을 쓸지" 정하는 절차다. 클라이언트가 ClientHello에 후보 목록(예: `h2`, `http/1.1`)을 제안하면, 서버가 ServerHello에서 하나를 골라 회신한다. 이 선택 결과가 곧 **"이 연결은 HTTP/2냐 HTTP/1.1이냐"** 를 결정한다.

**왜 프록시가 ALPN을 "제어"할 수 있고, 해야 하나.**
우리 프록시는 중간에서 TLS를 양쪽으로 종단한다(5주차 이중 세션). 그래서 **두 세션 각각의 ALPN을 프록시가 정할 수 있다:**
- 세션1(브라우저 ↔ 프록시): 프록시가 **서버 역할**이므로, 클라의 제안 중 무엇을 고를지 프록시가 결정.
- 세션2(프록시 ↔ 진짜 서버): 프록시가 **클라 역할**이므로, 무엇을 제안할지 프록시가 결정.

**왜 이게 중요한가 — h2와 1.1은 와이어가 완전히 다르다.**
- HTTP/1.1: 사람이 읽는 **텍스트** (`POST /path HTTP/1.1\r\n...`).
- HTTP/2: **바이너리 프레이밍 + HPACK 헤더 압축 + 스트림 멀티플렉싱**.

둘은 파서가 완전히 다르다. 그래서 **협상 결과가 뭐냐에 따라 처리 코드를 통째로 바꿔야 한다.** "HTTP/2 사용 여부를 안다"는 건 곧 "ALPN 결과가 `h2`인지 확인한다"는 뜻이고, "제어한다"는 건 "프록시가 그 협상을 원하는 방향으로 몬다"는 뜻이다.

### ② Plan A / Plan B 코드 — 방식이 정반대

**Plan A — h2를 피한다(다운그레이드).**
프록시가 ALPN을 **무조건 http/1.1로** 몰아서, h2 자체가 협상되지 않게 한다. 그러면 실브라우저(기본 h2)를 붙여도 양쪽이 1.1로 서고, 기존 1.1 파서가 전부 처리한다.
```cpp
static const unsigned char ALPN_HTTP11[] = { 8, 'h','t','t','p','/','1','.','1' };
// 세션1(서버役) 콜백: 클라가 뭘 제안하든 http/1.1만 고른다
static int alpnSelectHttp11(...) { ... 항상 http/1.1 선택 ... }
// 세션2(클라役): 서버에 http/1.1만 광고
SSL_set_alpn_protos(ussl, ALPN_HTTP11, sizeof(ALPN_HTTP11));
```
- **장점:** 코드 변경 최소, 기존 파서 재사용.
- **한계(문서화됨):** gRPC 같은 **h2-only 클라이언트**는 "1.1만 하자"는 제안을 거부 → handshake 실패. → Plan B에서 해소.
- 즉 Plan A의 "HTTP/2 여부 제어"는 **"h2를 못 쓰게 차단"** 쪽이다. h2를 감지해서 처리하는 게 아니라 회피한다.

**Plan B — h2를 그대로 협상하고 분기한다.**
ALPN에서 **h2를 우선 제안**하고, 협상 결과를 **검사**해서 h2/1.1로 갈라친다.
```cpp
static const unsigned char ALPN_H2[]   = { 2, 'h','2' };
static const unsigned char ALPN_BOTH[] = { 2,'h','2', 8,'h','t','t','p','/','1','.','1' };
// 세션1(서버役): 클라 제안 중 h2 우선, 없으면 1.1 (둘 다 지원)
static int alpnSelectPreferH2(...) { SSL_select_next_proto(..., ALPN_BOTH, ...); }
// 협상 결과가 h2인지 검사
static bool alpnIsH2(SSL* ssl) {
    const unsigned char* p; unsigned len;
    SSL_get0_alpn_selected(ssl, &p, &len);
    return (len == 2 && memcmp(p, "h2", 2) == 0);
}
```
그리고 `HandleConnectMITM()`에서:
```cpp
bool clientH2 = alpnIsH2(cssl);                         // ★ HTTP/2 사용 여부 판정
if (clientH2) SSL_set_alpn_protos(ussl, ALPN_H2, ...);  // 서버엔 클라와 같은 프로토콜만 광고
else          SSL_set_alpn_protos(ussl, ALPN_HTTP11, ...);
...
bool upstreamH2 = alpnIsH2(ussl);
if (clientH2 != upstreamH2) { ... 종료 ... }             // 프로토콜 번역 미구현 → 불일치면 종료
if (clientH2) { H2Bridge br; ...; runH2Bridge(&br); }   // h2 → nghttp2 브릿지
else          { ... proxyExchange11 루프 ... }           // 1.1 → 기존 파서
```
- 세션1과 세션2의 프로토콜을 **일치**시킨다(클라가 h2면 서버에도 h2만 제안) → h2↔1.1 번역을 회피.
- `clientH2`가 곧 "HTTP/2 사용 여부"의 코드적 실체다.
- **한계:** 클라와 서버가 서로 다른 프로토콜로 협상되면(드묾) `ALPN mismatch ... translation not implemented`로 종료.

> **정리:** 커리큘럼 7번을 "h2를 실제로 감지하고 그에 맞게 처리"로 읽으면 완전한 구현은 **Plan B**에 있다. `alpnIsH2()`가 사용 여부 검사, `alpnSelectPreferH2`/`SSL_set_alpn_protos`가 제어, 그 뒤 h2/1.1 분기가 처리다. Plan A는 "h2를 눌러버리는 제어"만 한다.

---

## 8. Chunked Transfer Encoding 처리

### ① 개념

**왜 chunked가 필요한가.**
`Content-Length`는 **body 크기를 미리 알아야** 쓸 수 있다. 그런데 서버가 데이터를 **생성하면서 동시에 흘려보내는** 경우(실시간 생성, 스트리밍)엔 전체 크기를 미리 모른다. 이때 쓰는 게 `Transfer-Encoding: chunked`다. "전체 크기는 몰라도, 지금 보낼 이 조각의 크기는 안다"는 발상이다.

**구조.**
각 조각 앞에 **16진수 크기**를 붙이고, **크기 0인 조각**으로 끝을 알린다.
```
5\r\nhello\r\n      ← 5바이트 조각
6\r\n world\r\n     ← 6바이트 조각
0\r\n\r\n           ← 크기 0 = 끝 (뒤에 trailer 헤더가 올 수도 있음)
```
- 크기는 **16진수**다(`a`면 10바이트, `10`이면 16바이트).
- `0` 조각이 종료 신호. Content-Length처럼 "총 몇 바이트"가 아니라 "0을 만날 때까지".

**프록시의 선택 — 디코드 vs 통과.**
프록시는 chunked를 (a) 조각들을 합쳐 하나의 body로 **디코드**하거나, (b) chunked 형식 **그대로 전달**할 수 있다. 우리는 중계가 목적이라 그대로 전달하되, 업로드 식별을 위해 **디청크된 실제 body 바이트만** 따로 캡처한다.

**★ HTTP/2엔 chunked가 없다.**
이게 중요하다. HTTP/2는 body를 **DATA 프레임**으로 나눠 보내므로 chunked encoding을 쓰지 않는다. RFC상 h2에서 `Transfer-Encoding: chunked`는 **금지**다. 따라서 chunked는 **HTTP/1.1 전용 개념**이고, h2에서는 nghttp2가 DATA 프레임을 알아서 처리한다.

### ② Plan A / Plan B 코드

**(1) chunked 감지.** `requestBodyMode`/`responseBodyMode`에서 `Transfer-Encoding`에 `chunked`가 있으면 `BodyMode::Chunked`.

**(2) chunked 전달 + 캡처.** 두 파일 모두 `SockReader::forwardChunked(dest, cap)`:
```cpp
bool forwardChunked(Stream* dest, std::string* cap = nullptr) {
    while (true) {
        std::string line; readLine(line);
        long long sz; parseHexChunkSize(line, sz);      // ★ 16진수 크기
        dest->writeAll(line + "\r\n");                  // 크기줄 그대로 전달
        if (sz == 0) { ...trailer 처리... return true; } // 0 = 끝
        forwardExact((size_t)sz, dest, cap);            // 조각 데이터 전달 (+ cap에 실제 바이트만)
        readExact(2, crlf); dest->writeAll(crlf);       // 조각 뒤 \r\n
    }
}
```
- `cap`이 있으면 **디청크된 실제 body 바이트만** `uploadCap`에 모은다. 그래서 업로드가 chunked로 와도 `scanMultipart`가 파일명을 정확히 뽑는다(크기줄·`\r\n` 같은 프레이밍은 캡처에서 제외).

**(3) 어느 경로에서 쓰나.**
- **Plan A:** 평문 HTTP 경로 + MITM 1.1 경로에서 사용.
- **Plan B:** **1.1 fallback 경로(`proxyExchange11`)에서만** 사용한다.
  ```cpp
  else if (reqMode == BodyMode::Chunked) { if (!cr.forwardChunked(uOut, capPtr)) return false; }
  ```
  **h2 브릿지 경로엔 chunked 처리가 없다** — 그게 정상이다. h2는 body가 DATA 프레임으로 오고, `cb_on_data_chunk` 콜백이 그 바이트를 받는다(chunked가 아니라 프레임). 즉 8번은 Plan B의 1.1 경로에만 존재하고, h2 경로에선 개념 자체가 없다.

> **정리:** chunked = "크기 모를 때 조각조각(16진수 크기, 0=끝)". 두 파일 다 `forwardChunked`로 처리하며 실제 body만 캡처한다. 단 **HTTP/2엔 chunked가 없으므로** Plan B의 h2 경로엔 이 로직이 없고 nghttp2의 DATA 프레임이 그 자리를 대신한다.

---

## 9. Content-Encoding 압축 데이터 처리

### ① 개념 (자세히)

**Content-Encoding이 뭔가.**
`Content-Encoding: gzip`(또는 `br`=brotli, `deflate`)은 **body를 압축해서 전송**하는 것이다. 대역폭을 아끼려고 서버가 HTML·JSON 같은 응답을 압축해 보내고, 받는 쪽이 해제해서 쓴다. 클라이언트는 요청 헤더에 `Accept-Encoding: gzip, deflate, br`로 "나 이 방식들 해제할 수 있어"라고 알리고, 서버는 그중 하나를 골라 `Content-Encoding`으로 응답에 표시한다.

**왜 압축이 되는가 — 정보이론 관점.**
텍스트(HTML/JSON/JS)는 **중복(redundancy)** 이 많다. `<div class="`가 파일에 수백 번 나오고, 알파벳 빈도도 고르지 않다(`e`가 `z`보다 훨씬 흔함). 압축은 이 통계적 편향과 반복을 이용해 "같은 정보를 더 적은 비트로" 표현하는 것이다. 완전히 무작위(랜덤)한 데이터는 중복이 없어 압축이 거의 안 된다 — 이미 압축된 파일(zip, jpg)을 다시 압축해도 안 줄어드는 이유다.

**DEFLATE 알고리즘 — gzip과 zlib의 심장.**
gzip과 zlib이 쓰는 압축 알고리즘은 **DEFLATE**(RFC 1951)이고, 두 가지 기법을 합친 것이다:

1. **LZ77 (사전 기반 중복 제거)** — 지금까지 나온 데이터를 "슬라이딩 윈도우"(최근 32KB)로 들고 있다가, 지금 나올 문자열이 그 윈도우 안에 이미 있으면 **문자열 통째로 대신 "(거리, 길이)" 참조 한 쌍**만 적는다. 예: `"hello world hello"` → `hello world`를 다 쓴 뒤 `hello`가 다시 나오면 `(거리=12, 길이=5)`로 대체. 반복이 많을수록 압축률이 높다.
2. **허프만 코딩 (빈도 기반 비트 절약)** — 자주 나오는 심볼(문자, 또는 LZ77 결과)에 **짧은 비트코드**를, 드문 심볼에 긴 비트코드를 배정한다. 모스 부호가 `e`를 점 하나로 하는 것과 같은 발상 — 전체 평균 비트 수를 줄인다.

DEFLATE는 이 둘을 **순서대로** 적용한다: 먼저 LZ77로 반복을 참조로 바꾸고, 그 결과(리터럴+참조들)를 허프만으로 다시 압축.

**포맷 삼총사 — gzip / zlib / raw deflate (여기서 헷갈림이 제일 많이 남)**
셋 다 내부 압축 알고리즘은 **동일한 DEFLATE**지만, **감싸는 헤더/트레일러(포장지)가 다르다:**

| 포맷 | 헤더 | 트레일러 | 식별 |
|---|---|---|---|
| **gzip** | 10바이트 (매직 `1f 8b`, 압축방식, 플래그, 시간 등) | 8바이트 (CRC32 + 원본 길이) | 매직바이트 `1f 8b`로 구분 |
| **zlib** | 2바이트 (CMF/FLG) | 4바이트 (Adler-32 체크섬) | 첫 바이트 상위 니블이 보통 `0x78` |
| **raw deflate** | 없음 | 없음 | 헤더가 없어 자동식별 불가 |

`Content-Encoding: gzip`이면 보통 gzip 포맷(매직 `1f 8b`)이고, `Content-Encoding: deflate`는 스펙상 zlib 포맷이 맞지만 **일부 서버가 실수로 raw deflate를 보내는** 유명한 상호운용성 버그가 있다(브라우저들은 그래서 관대하게 둘 다 시도). 이 셋을 구분 못 하고 해제 코드를 짜면 "왜 안 풀리지"의 흔한 원인이 된다.

**Brotli(`br`) — 구글이 만든 더 최신 알고리즘.**
Brotli(2013년 공개, 2015년부터 웹 표준)는 LZ77+허프만이라는 기본 골격은 DEFLATE와 비슷하지만 결정적 차이가 있다: **~120KB짜리 내장 정적 사전(static dictionary)** 을 갖고 있다. 이 사전엔 HTML 태그, 흔한 JS/CSS 키워드, 자주 쓰이는 영어 구절 등 **"웹에서 흔히 나오는 문자열"이 미리 들어있어서**, 압축할 파일 안에 그 내용이 없어도 사전을 참조해 바로 압축할 수 있다. 그래서 **웹 콘텐츠 한정으로 gzip보다 15~25% 더 작게 압축**되는 경우가 많고, 크롬이 `Accept-Encoding`에서 `br`을 gzip보다 먼저(우선) 제안하는 이유다. brotli는 자체 라이브러리(구글 `brotli`)가 필요하고 zlib과 API가 다르다.

**Transfer-Encoding(chunked, 8번)과 절대 헷갈리지 말 것 — 완전히 다른 축.**

| | Transfer-Encoding: chunked (8번) | Content-Encoding: gzip/br (9번) |
|---|---|---|
| 무엇을 다루나 | body를 **어떻게 쪼개 보내나**(전송 프레이밍) | body **내용을 어떻게 압축했나**(내용 인코딩) |
| 층 | 전송(transfer) 층 | 표현(representation) 층 |
| 동시 가능? | | **예 — chunked + gzip 동시 가능** |

즉 chunked로 쪼개 보낸 각 조각을 다 합쳐야 비로소 "온전한 압축 스트림"이 되고, 그걸 gzip/brotli로 풀어야 진짜 body가 나온다. 순서: **① chunked 조각들을 합친다 → ② 그 결과를 압축 해제한다.**

**★ HPACK과 헷갈리지 말 것 — Plan B에서 핵심 오해 지점.**
HTTP/2엔 압축이 두 군데 있다:
- **HPACK** = h2의 **헤더** 압축(RFC 7541, 정적/동적 테이블 기반). → nghttp2가 **자동으로 푼다.**
- **Content-Encoding** = **body** 압축(지금 다루는 것). → nghttp2가 **안 푼다.** 이건 h2든 1.1이든 동일한 상위 계층이다.

층으로 보면:
```
[TLS]                         ← OpenSSL이 벗김
  [HTTP/2 프레이밍 + HPACK]    ← nghttp2가 벗김 (h2 헤더까지 평문)
    [Transfer-Encoding: chunked]  ← forwardChunked 가 벗김 (8번, h2엔 없음)
      [Content-Encoding: gzip/br] ← 아무도 안 벗김  ★ 9번, 미구현
        [실제 body 바이트]
```
그래서 "Plan B는 nghttp2를 쓰니 압축이 풀리겠지"는 **틀린 기대**다. nghttp2는 헤더 압축(HPACK)만 풀지 body 압축(Content-Encoding)은 건드리지 않는다.

**스트리밍 압축 해제라는 개념도 알아둘 것.**
압축 데이터는 네트워크로 조금씩(TCP 조각, h2 DATA 프레임 단위) 나눠서 온다. zlib의 `inflate()`와 brotli의 `BrotliDecoderDecompressStream()`은 **"압축 데이터를 전부 모으기 전에, 들어오는 대로 조금씩 먹여서 조금씩 평문을 뽑아낼 수 있는" 스트리밍 API**다. 이게 왜 중요하냐면, "완전한 압축 파일을 통째로 받아야만 풀 수 있다"는 방식(예: 파일 전체를 압축한 zip)과 달리, **HTTP body 압축 스트림은 부분 데이터만 있어도 그 부분까지는 해제가 가능**하기 때문이다 — 우리 프록시처럼 캡처 상한(cap)이 있는 상황에서도 "상한까지 받은 만큼은 해제"가 가능한 이유가 이것이다.

### ② Plan A / Plan B 현재 상태

**둘 다 미구현이다.** 각 파일 한계 블록에 명시돼 있다:
- Plan A: `Content-Encoding(gzip/br) 로 압축된 body 는 아직 해제 안 함 → 압축된 요청/응답 본문은 평문 스캔 불가(다음 작업).`
- Plan B: `Content-Encoding(gzip/br) 미해제 — 압축 body 는 평문 스캔 불가.`

**왜 미구현인데도 통신·탐지엔 지장이 없나.**
- **통신:** 프록시는 리버스 프록시라 **압축된 body를 브라우저로 그대로 통과**시킨다. 브라우저엔 gzip/br 해제기가 있으니 정상적으로 본다. 즉 사용자 통신은 멀쩡하다.
- **파일 탐지:** 우리가 잡으려는 **업로드 요청 body(multipart)** 는 브라우저가 압축하지 않는다 → **평문**이라 `scanMultipart`가 그대로 읽는다. 그래서 파일 업로드 식별은 9번 없이도 된다.

**그럼 9번이 언제 필요한가.**
**우리 프록시가 직접 body를 읽으려 할 때**만이다 — 서버 **응답 body**(구글이 br로 압축)를 우리가 로그로 찍거나 스캔하려면 해제가 필요하다. "피들러처럼 응답 본문까지 눈으로 읽기"를 하려면 9번이 선행돼야 한다.

### ③ 실제 구현 방법 — 라이브러리부터 코드까지

**1단계 — 라이브러리 설치 (vcpkg).**
```bat
vcpkg install zlib:x64-windows brotli:x64-windows
```
- `zlib`는 gzip과 zlib 포맷을 **둘 다** 다룰 수 있다(옵션 하나로 전환). deflate 알고리즘 자체가 zlib이 원조라, gzip 해제도 zlib 라이브러리로 한다 — 별도로 "gzip 라이브러리"는 없다.
- `brotli`는 구글이 공개한 별개 라이브러리(`brotlidec`가 디코더 부분).

**2단계 — 헤더/링크 추가.**
파일 상단(다른 `#pragma comment(lib, ...)` 옆)에:
```cpp
#include <zlib.h>
#include <brotli/decode.h>
...
#pragma comment(lib, "zlib.lib")          // vcpkg triplet에 따라 zlibstatic.lib일 수도 있음 — 빌드 후 확인
#pragma comment(lib, "brotlidec.lib")
#pragma comment(lib, "brotlicommon.lib")
```

**3단계 — gzip/zlib 해제 함수 (zlib API).**
zlib의 `inflateInit2`에 `windowBits`를 **`15 + 32`** 로 주면 **gzip과 zlib 포맷을 자동 감지**해서 풀어준다(앞서 말한 "포맷 삼총사" 문제를 라이브러리가 대신 해결).
```cpp
static bool inflateGzipOrZlib(const std::string& in, std::string& out) {
    z_stream zs{};
    // ★ windowBits = 15+32 → gzip(1f 8b)과 zlib(78 xx) 헤더를 자동 인식
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return false;
    zs.next_in  = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();

    char buf[16384];
    int ret;
    do {
        zs.next_out  = (Bytef*)buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);              // ★ 스트리밍 API — 부분 입력도 처리
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            inflateEnd(&zs);
            return false;                             // 손상되었거나 우리 캡처가 잘린 경우
        }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (zs.avail_out == 0 && ret != Z_STREAM_END);

    inflateEnd(&zs);
    return true;   // Z_STREAM_END 까지 못 갔어도 out 에 담긴 만큼은 유효한 평문(캡처 상한으로 잘린 경우)
}
```

**4단계 — brotli 해제 함수 (brotli API).**
```cpp
static bool brotliDecompress(const std::string& in, std::string& out) {
    BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!state) return false;

    const uint8_t* next_in = (const uint8_t*)in.data();
    size_t avail_in = in.size();
    char buf[16384];
    BrotliDecoderResult result;

    do {
        uint8_t* next_out = (uint8_t*)buf;
        size_t avail_out = sizeof(buf);
        result = BrotliDecoderDecompressStream(state, &avail_in, &next_in,
                                               &avail_out, &next_out, nullptr);
        out.append(buf, sizeof(buf) - avail_out);
    } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

    bool ok = (result == BROTLI_DECODER_RESULT_SUCCESS);
    BrotliDecoderDestroyInstance(state);
    return ok;   // ok=false 여도 out 에 여기까지 풀린 평문은 남아있음(캡처가 잘린 경우 부분 성공)
}
```

**5단계 — Content-Encoding 헤더로 분기하는 디스패처.**
```cpp
static bool decodeContentEncoding(const std::string& encoding, const std::string& in, std::string& out) {
    std::string enc = toLower(encoding);
    if (enc.find("br") != std::string::npos)                                   return brotliDecompress(in, out);
    if (enc.find("gzip") != std::string::npos || enc.find("deflate") != std::string::npos)
                                                                                return inflateGzipOrZlib(in, out);
    out = in; return true;   // "identity" 또는 명시 안 됨 → 압축 안 됨, 그대로
}
```
> 참고: `Content-Encoding`은 드물게 `gzip, br`처럼 **여러 개를 콤마로 나열**할 수 있다(적용 순서의 역순으로 풀어야 함). 실무에서 거의 안 쓰이므로 위 디스패처는 단일 인코딩만 가정 — 필요하면 콤마로 split해서 뒤에서부터 반복 적용.

**6단계 — 기존 코드에 훅 걸기 (위치 정확히).**

- **Plan A / Plan B의 1.1 경로:** 응답 헤더를 읽은 직후, body를 `forwardExact`/`forwardChunked`로 넘기면서 캡처한 뒤(업로드 캡처와 같은 패턴으로 응답 body도 별도 버퍼에 캡처 필요 — 지금은 요청 body만 캡처하므로 응답용 캡처 버퍼 추가가 선행돼야 함):
  ```cpp
  // readHead(up, resp) 로 응답 헤더 읽은 직후
  std::string ctEnc = headerGet(resp, "content-encoding");
  // ... respMode 로 body 를 캡처하며 전달 ...
  if (!ctEnc.empty()) {
      std::string decoded;
      if (decodeContentEncoding(ctEnc, respBodyCap, decoded))
          logBlock("  [decoded body, " + std::to_string(decoded.size()) + " bytes]\n"
                   + decoded.substr(0, 2000) + "\n");   // 로그 폭주 방지로 앞부분만
      else
          logMsg("  [decode failed] encoding=" + ctEnc);
  }
  ```
- **Plan B의 h2 경로:** `cb_on_frame_recv`에서 응답 DATA 프레임이 `endStream`(=`s->respEof = true`)이 되는 시점, `submitClientResponse` 호출 직전/직후에 `s->respHdr`에서 `content-encoding`을 찾아 `s->respBody`(이미 `cb_on_data_chunk`가 모아둔 응답 body)에 대해 동일하게 `decodeContentEncoding` 호출.

**정리:** 9번을 구현한다는 건 "라이브러리 두 개(zlib, brotli)를 붙이고, 응답 body 캡처 지점 뒤에 `decodeContentEncoding` 한 줄을 끼워 넣는 것"이다. h2를 하든 안 하든 이 로직은 완전히 동일하다 — nghttp2(HPACK)와는 다른 별개 층이기 때문. 업로드 탐지(요청 multipart, 무압축)엔 불필요하고, **응답 본문을 우리가 읽고 싶을 때** 필요하다.

---

## 마무리 — 네 항목의 관계

- **6번(Keep-Alive 경계)** 과 **8번(chunked)** 은 **HTTP/1.1 전용** 이슈다. body의 끝을 아는 방법(Content-Length / chunked / close)이 곧 경계 판정이고, 그 위에서 keep-alive 루프가 돈다. Plan B의 h2 경로에선 스트림/프레임으로 대체돼 이 문제들이 사라진다.
- **7번(ALPN/HTTP2)** 은 "1.1로 갈지 h2로 갈지"를 정하는 갈림길이다. Plan A는 1.1로 강제(6·8번 로직으로 흡수), Plan B는 h2면 nghttp2 브릿지로 분기.
- **9번(Content-Encoding)** 은 1.1이든 h2든 **공통으로 얹히는 별개 층**이고, 둘 다 아직 미구현이다.

즉 6·7·8은 "전송을 정확히 받아내는" 문제고, 9는 "받은 body의 내용을 읽으려면 추가로 풀어야 하는" 문제다. 우리 프로젝트 목표(업로드 식별)는 6·7·8까지로 충족되고, 9는 "응답 본문까지 사람이 읽는 피들러급 가시화"로 갈 때의 다음 과제다.
