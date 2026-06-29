# Local Proxy 기반 네트워크 트래픽 분석 PoC 1차 보고서 (주차별 버전)

## 1. 서론

### 1.1 연구 배경

웹 브라우저, 업무용 애플리케이션, AI Agent 등 다양한 클라이언트 환경에서 외부 서비스로 파일과 데이터가 전송되는 사례가 증가하고 있다. 이러한 환경에서는 조직 보안 정책상 허용되지 않은 파일 업로드가 발생할 수 있으며, 이를 네트워크 수준에서 식별하고 분석할 수 있는 구조가 필요하다.

네트워크 통신은 단순히 클라이언트가 서버로 데이터를 보내는 과정처럼 보이지만, 실제로는 여러 통신 계층을 거쳐 처리된다. 사용자가 브라우저에서 웹사이트에 접속하면 브라우저는 HTTP 요청을 생성하고, 해당 요청은 TCP/IP 계층을 거쳐 서버로 전달된다. 서버는 요청을 처리한 뒤 HTTP 응답을 생성하고, 응답은 다시 네트워크를 통해 클라이언트로 전달된다.

본 연구에서는 이러한 통신 흐름을 분석하기 위해 Local Proxy 구조를 활용한다. Local Proxy는 클라이언트와 서버 사이에 위치하여 요청과 응답을 중계하고, 그 과정에서 HTTP Method, Host, Header, Content-Type, Content-Length, body 존재 여부 등을 분석할 수 있다.

### 1.2 연구 목적

본 연구의 목적은 Local Proxy를 이용하여 클라이언트와 서버 사이의 네트워크 트래픽을 분석하고, 최종적으로 파일 업로드 행위를 식별할 수 있는 가능성을 검증하는 것이다.

본 과제는 PoC(Proof of Concept) 성격의 연구이다. PoC는 특정 기술 구조나 아이디어가 실제로 가능한지 검증하기 위한 실험적 구현을 의미한다. 따라서 본 연구는 상용 제품 수준의 완전한 보안 기능을 구현하는 것이 아니라, Local Proxy 기반 분석 구조가 실제로 동작 가능한지 확인하는 데 초점을 둔다.

### 1.3 1차 보고서 범위

본 1차 보고서는 다음 내용을 포함한다.

- OSI 7계층과 실제 통신 흐름 학습
- TCP/IP 및 Socket 통신 구조 학습
- Proxy 및 Local Proxy 개념, Explicit/Transparent Proxy 비교
- TCP 기반 Local Proxy 중계 구조 구현
- HTTP 요청/응답 구조 분석 (Request Line, Header, body 경계)
- Content-Type 기반 multipart/form-data 파일 업로드 가능성 탐지

본 단계에서는 HTTPS 복호화, TLS MITM, 인증서 처리, 파일 바이너리 추출, 정책 기반 차단은 구현 범위에 포함하지 않는다. HTTPS 트래픽은 TLS 암호화로 인해 단순 TCP/HTTP Proxy만으로는 내용을 확인할 수 없으므로, HTTPS 분석 구조는 후속(5주차 이후) 범위로 분리한다.

---

## 2. 네트워크 통신 기본 구조

### 2.1 OSI 7계층

OSI 7계층은 네트워크 통신 과정을 7개의 계층으로 나누어 설명하는 개념 모델이다. 송신 측에서는 데이터가 상위 계층에서 하위 계층으로 내려가며 전송 가능한 형태로 변환되고, 수신 측에서는 하위 계층에서 상위 계층으로 올라가며 복원된다.

| 계층 | 이름 | 주요 역할 | 예시 |
|------|------|-----------|------|
| 7 | Application | 응용 서비스 | HTTP, HTTPS, FTP |
| 6 | Presentation | 데이터 표현, 인코딩, 암호화 | 인코딩, 압축, TLS |
| 5 | Session | 통신 세션 관리 | 연결 관리 |
| 4 | Transport | 프로세스 간 데이터 전송 | TCP, UDP |
| 3 | Network | 목적지 경로 결정 | IP |
| 2 | Data Link | 같은 네트워크 구간 전달 | Ethernet, MAC |
| 1 | Physical | 물리 신호 전송 | 케이블, Wi-Fi |

본 프로젝트에서 Local Proxy가 다루는 계층은 두 곳이다. 바이트를 운반하는 것은 4계층(TCP)이고, 그 바이트를 Method/URL/Header/body로 해석하는 것은 7계층(HTTP)이다.

### 2.2 클라이언트-서버 통신 흐름

사용자가 `http://example.com`에 접속하는 경우:

1. 브라우저가 HTTP 요청을 생성한다.
2. 클라이언트가 서버와 TCP 연결을 수립한다.
3. 요청이 TCP/IP 계층을 거쳐 서버로 전송된다.
4. 서버가 요청을 처리하고 HTTP 응답을 생성한다.
5. 응답이 다시 클라이언트로 전달된다.
6. 브라우저가 응답을 해석하여 화면에 표시한다.

### 2.3 TCP/IP와 Socket

TCP는 연결 지향형 전송 프로토콜이다. 데이터를 주고받기 전에 연결을 먼저 수립한다.

서버 측 흐름: `socket → bind → listen → accept → recv/send → closesocket`
클라이언트 측 흐름: `socket → connect → send/recv → closesocket`

Windows에서는 Winsock API를 사용하므로 소켓 사용 전 `WSAStartup`을 호출한다. Local Proxy는 클라이언트를 받는 서버 역할과 원 서버로 연결하는 클라이언트 역할을 동시에 수행하므로 두 흐름을 모두 사용한다.

### 2.4 HTTP 통신 흐름

HTTP는 요청/응답 기반의 평문 프로토콜이다.

HTTP 요청은 Request Line(Method, Path, Version), Header(Host, Content-Type, Content-Length 등), Body로 구성된다. HTTP 응답은 Status Line(Version, Status Code, Reason), Header, Body로 구성된다. Header와 Body는 빈 줄(CRLF)로 구분된다.

---

## 3. Proxy 기반 트래픽 분석 구조

### 3.1 Proxy와 Local Proxy

Proxy는 클라이언트와 서버 사이에서 요청과 응답을 중계하는 중간 구성 요소이다. 클라이언트 입장에서는 서버처럼, 서버 입장에서는 클라이언트처럼 동작한다. Local Proxy는 사용자 PC 내부(127.0.0.1)에서 실행되는 Proxy로, 요청을 중간에서 확인하여 Method, Host, Header, Content-Type 등을 분석할 수 있다.

### 3.2 Explicit Proxy와 Transparent Proxy

| 구분 | Explicit Proxy | Transparent Proxy |
|------|----------------|-------------------|
| 클라이언트 인지 | 명시적으로 인지 | 인지하지 못함 |
| 설정 방식 | 클라이언트가 Proxy 주소 직접 설정 | OS/네트워크 계층 리다이렉션 |
| 구현 난이도 | 낮음 | 높음 |
| 목적지 정보 | 요청(Host)에서 확인 | 리다이렉션 Context로 복원 |
| 본 PoC 적용 | 현재 방식 | 향후 확장(WFP) |

본 PoC 초기 단계에서는 구현·테스트 편의성을 위해 Explicit Proxy 방식을 우선 사용한다. curl에서 `-x http://127.0.0.1:18080` 으로 Proxy를 지정하면 요청이 Local Proxy를 경유한다.

---

## 4. 주차별 학습 및 구현 내용

### 4.1 1주차: 기본 개념 학습

1주차에서는 Local Proxy 기반 네트워크 분석 PoC의 목적과 전체 방향을 이해하였다. 네트워크 통신, OSI 7계층, TCP/IP, Proxy, HTTP 요청/응답 구조 등 프로젝트 수행에 필요한 기본 개념을 학습하였다.

또한 TCP 통신의 기본 구조를 이해하기 위해 단순 송수신 서버/클라이언트를 작성하여, "서버는 연결을 기다리는 쪽, 클라이언트는 연결을 요청하는 쪽"이라는 기본 구조를 확인하였다.

### 4.2 2주차: 통신 구조 및 Proxy 동작 방식 학습

2주차에서는 클라이언트-서버 통신 흐름을 구체적으로 학습하고 Proxy의 동작 방식을 분석하였다. 일반 통신에서는 클라이언트가 서버에 직접 연결하여 중간에서 트래픽을 분석하기 어렵다. 따라서 클라이언트와 서버 사이에 Local Proxy를 배치하여 분석 지점을 확보한다.

Explicit Proxy와 Transparent Proxy의 차이를 학습하고, 초기 단계에서는 구현·테스트가 용이한 Explicit Proxy 방식을 우선 적용하기로 하였다.

### 4.3 3주차: TCP 기반 Local Proxy 중계 구조 구현

3주차에서는 TCP 기반 Local Proxy의 중계 구조를 구현하였다. Proxy는 클라이언트 연결을 수락하고, 원 서버와 별도의 TCP 연결을 생성한 뒤, 클라이언트 요청과 서버 응답을 중계한다.

구현 흐름:

1. listen 소켓을 생성하여 127.0.0.1:18080에서 연결을 대기한다.
2. 클라이언트 연결을 수락한다(연결마다 독립 스레드).
3. 클라이언트 요청을 수신한다.
4. 요청에서 대상 host를 식별하고 `getaddrinfo`로 IP를 얻어 원 서버에 연결한다.
5. 클라이언트 요청을 원 서버로 전달한다.
6. 원 서버 응답을 수신하여 클라이언트로 전달한다.

3주차의 핵심은 HTTP 분석이 아니라, Proxy가 실제 중간 전달자로 동작하는지 확인하는 것이다. 본 구현은 송수신을 정확히 처리하기 위해 부분 전송 대비 전량 송신(`sendAll`)을 적용하였다.

### 4.4 4주차: HTTP 요청/응답 분석 및 업로드 가능성 탐지

4주차에서는 중계되는 데이터를 단순 전달하는 수준을 넘어, 어떤 HTTP 요청인지 해석하는 기능을 추가하였다.

구현 항목:

1. Request Line 파싱 → Method, URL, Version 추출
2. Header 파싱 → Host, Content-Type, Content-Length 등
3. Header와 Body 경계 식별
4. body 길이 판정 (Content-Length / chunked)
5. Content-Type 기반 multipart/form-data 업로드 가능성 탐지
6. 응답 Status 파싱
7. 분석 결과 로그 출력

TCP는 바이트 스트림이므로 `recv` 한 번이 메시지 하나와 일치하지 않는다. 이를 처리하기 위해 버퍼드 리더(`SockReader`)를 두어, 줄 단위 읽기와 N바이트 정확히 읽기, 잉여 바이트 보관을 통해 메시지 경계를 정확히 식별한다.

또한 Content-Type이 `multipart/form-data`인 경우 파일 업로드 가능성이 있는 요청으로 분류한다. 본 단계에서는 파일 내용을 추출하지 않으며, 해당 요청을 업로드 의심 요청으로 표시하는 수준이다.

---

## 5. 코드 구성 및 동작 설명

본 단계 구현은 단일 프로그램(`proxy_arch.cpp`)으로 통합되어 있으며, 주요 구성 요소는 다음과 같다.

| 구성 요소 | 역할 |
|-----------|------|
| `RunServer` | listen 소켓 생성, accept 루프, 연결마다 스레드 분리 |
| `HandleClient` | 요청 수신 및 처리 진입 |
| `HandleHttp` | HTTP 파싱 루프 (요청·응답 처리, multipart 판별, keep-alive) |
| `SockReader` | TCP 스트림 버퍼드 리더 |
| `readHead` / `HttpHead` | Request Line + Header 파싱 |
| `BodyMode` 판정 | Content-Length / chunked / 없음 구분 |
| `ConnectUpstream` | `getaddrinfo` + `connect`로 원 서버 연결 |
| `sendAll` | 부분 전송 대비 전량 송신 |

Local Proxy는 두 종류의 소켓을 사용한다. client socket은 클라이언트와 연결되어 요청 수신·응답 송신에 사용하고, upstream socket은 원 서버와 연결되어 요청 송신·응답 수신에 사용한다.

HTTP 요청 처리 흐름:

1. 클라이언트 요청 head 수신 및 파싱
2. Method, URL, Version 추출
3. Host, Content-Type, Content-Length 추출
4. Header와 Body 경계 확인
5. multipart/form-data 여부 확인
6. 원 서버 연결 및 요청 전달
7. 응답 파싱 및 클라이언트 전달
8. 분석 결과 로그 출력

---

## 6. 테스트 및 검증

### 6.1 테스트 환경

- 프록시: `proxy_arch.exe` 가 `127.0.0.1:18080` 에서 실행
- 클라이언트: curl (Explicit Proxy 방식)
- 대상 서버: `postman-echo.com` (요청을 echo하는 테스트 서버)

아래 로그는 실제 실행하여 프록시 콘솔에 출력된 결과이다(mock 아님).

```
[proxy_arch] :18080  (HTTP + HTTPS tunnel)
[http] GET    http://postman-echo.com/get -> 200
[http] POST   http://postman-echo.com/post -> 200
[http] POST   http://postman-echo.com/post -> 200  [upload? multipart/form-data]
```

### 6.2 HTTP GET 요청 분석

```
curl -x http://127.0.0.1:18080 http://postman-echo.com/get
```

| 항목 | 실측 값 |
|------|---------|
| Method | GET |
| URL | http://postman-echo.com/get |
| Status | 200 |
| 업로드 의심 | 없음 |

### 6.3 HTTP POST(JSON) 요청 분석

```
curl -x http://127.0.0.1:18080 -X POST -H "Content-Type: application/json" -d "{\"name\":\"test\"}" http://postman-echo.com/post
```

| 항목 | 실측 값 |
|------|---------|
| Method | POST |
| URL | http://postman-echo.com/post |
| Content-Type | application/json |
| Status | 200 |
| 업로드 의심 | 없음 |

### 6.4 파일 업로드(multipart) 요청 분석

```
curl -x http://127.0.0.1:18080 -F "file=@test.txt" http://postman-echo.com/post
```

| 항목 | 실측 값 |
|------|---------|
| Method | POST |
| URL | http://postman-echo.com/post |
| Content-Type | multipart/form-data |
| Status | 200 |
| 업로드 의심 | 탐지됨 (`[upload? multipart/form-data]`) |

세 요청 모두 프록시를 정상 경유하여 200 응답을 받았으며, multipart 요청은 업로드 가능성 요청으로 정확히 분류되었다.

---

## 7. 현재 한계점

### 7.1 HTTP/1.1 평문 중심

분석 대상은 HTTP/1.1 평문 요청이다. HTTPS와 같이 암호화된 통신은 본 단계 범위에 포함하지 않는다.

### 7.2 I/O 동시성 모델

본 구현은 blocking 소켓 + 연결당 스레드 1개 모델을 사용한다. 연결 수가 많아지면 스레드 수가 비례 증가하므로, 대규모 동시성에는 non-blocking 소켓과 이벤트 루프(epoll/IOCP) 기반 구조가 필요하다.

### 7.3 파일 데이터 추출 미적용

현재는 Content-Type 기반 업로드 가능성 판별까지 수행한다. 파일명(Content-Disposition), MIME Type, boundary 파싱, 파일 바이너리 추출은 후속 단계 범위이다.

### 7.4 HTTPS 분석은 후속 단계 범위

HTTPS는 TLS 암호화로 인해 단순 TCP/HTTP Proxy 구조만으로는 내용을 확인할 수 없다. HTTPS 분석을 위한 TLS 구조, 인증서 처리, 복호화 구조는 후속(5주차 이후) 범위로 분리한다.

### 7.5 Transparent Proxy 미구현

현재는 Explicit Proxy 기반이다. Transparent Proxy 구조는 Windows WFP 기반 리다이렉션과 목적지 복원이 필요하므로 후속 확장 범위로 분리한다.

---

## 8. 향후 개발 계획

| 단계 | 내용 |
|------|------|
| 5주차 | HTTPS 분석을 위한 TLS 세션 구조, 인증서 신뢰 체계 학습 |
| 6주차 이후 | TLS MITM 기반 HTTPS 요청/응답 평문 분석 구조 검토 |
| 파일 식별 확장 | multipart/Content-Disposition/filename 기반 파일 업로드 행위 식별 |
| 데이터 추출 | 파일명, 확장자, MIME Type, 파일 바이너리 추출 및 검증 |
| 최종 정리 | 전체 결과 보고서 및 발표 자료 작성 |

---

## 9. 결론

본 1차 보고서에서는 Local Proxy 기반 네트워크 트래픽 분석 PoC를 위해 수행한 학습 및 구현 내용을 정리하였다.

1주차에서는 OSI 7계층, TCP 통신, HTTP 요청/응답 구조 등 기본 개념을 학습하고 소켓 통신의 기본 흐름을 확인하였다. 2주차에서는 Proxy와 Local Proxy 동작 구조, Explicit/Transparent Proxy의 차이를 정리하고 Explicit Proxy 방식을 우선 적용하기로 하였다. 3주차에서는 TCP 기반 Local Proxy의 중계 구조를 구현하여 Proxy가 중간 전달자로 동작함을 확인하였다. 4주차에서는 HTTP 요청/응답을 파싱하여 Method, Host, Header, Content-Type, body 존재 여부를 식별하고, Content-Type 기반으로 파일 업로드 가능성을 탐지하는 기능을 구현하였다.

현재 단계에서는 HTTP/1.1 평문 트래픽 분석과 업로드 가능성 탐지까지의 구조를 실제 실행 로그로 검증하였다. HTTPS 분석, 파일 바이너리 추출, 정책 기반 차단, Transparent Proxy(WFP)는 후속 단계에서 단계적으로 확장할 예정이다.

---

## 부록 A. 주요 용어

| 용어 | 설명 |
|------|------|
| OSI 7계층 | 네트워크 통신을 7개 계층으로 나누어 설명하는 모델 |
| PoC | Proof of Concept. 기술 구조의 실현 가능성을 검증하는 실험적 구현 |
| TCP | 연결 지향형 전송 프로토콜 |
| Socket | 네트워크 통신을 위한 프로그래밍 인터페이스 |
| Winsock | Windows의 소켓 프로그래밍 API |
| Proxy | 클라이언트와 서버 사이에서 요청/응답을 중계하는 구성 요소 |
| Local Proxy | 사용자 PC 내부(127.0.0.1)에서 실행되는 Proxy |
| Explicit Proxy | 클라이언트가 Proxy 주소를 명시적으로 설정하는 방식 |
| Transparent Proxy | 클라이언트가 인지하지 못한 채 요청이 Proxy로 전달되는 방식 |
| Request Line | HTTP 요청 첫 줄. Method, Path, Version |
| Content-Type | body 데이터 형식을 나타내는 Header |
| multipart/form-data | 파일 업로드 시 자주 사용되는 HTTP body 형식 |
| keep-alive | 하나의 연결에서 여러 요청을 연속 처리하는 방식 |
