# 프로젝트 목표 & 로드맵 — Local Proxy 기반 네트워크 패킷 분석 PoC

> (A) 공식 인턴 커리큘럼(장동혁 책임님), (B) 참고용 목표 아키텍처(NetFlow),
> (C) 그 안에서 내가 할 일에 대한 해석/로드맵을 정리한 문서.

---

## ⚠️ 가장 중요한 전제 2가지

1. **처음부터 전부 직접 만든다.** 기존 MITM/NetFlow에 "추가"하는 게 아니다.
   아래 NetFlow 아키텍처는 **참고/맥락**이지 가져다 쓰는 코드가 아니다.

2. **현재 단계 범위 = Local Proxy ~ 파일 업로드 탐지.  WFP(커널 드라이버)는 "그 다음 단계".**
   - 공식 10주 커리큘럼(아래 §A)에는 WFP가 **없지만**, **로컬 프록시가 전부 완성된 이후에 WFP를 진행할 예정**이다.
     → 즉 **제외가 아니라 "나중에"(조건부: 로컬 완성 후)**.
   - 그래서 지금~당분간은 **유저모드 Local Proxy**에 집중한다.
   - 이 단계의 트래픽 유도는 (WFP transparent redirect가 아니라) **Explicit Proxy**
     — 브라우저/시스템 프록시 설정 또는 `curl -x`. (WFP transparent redirect는 로컬 완성 후 단계에서)

---

## A. 공식 인턴 커리큘럼 (10주) — 권위 있는 범위 기준

> "정확히 이대로 따라가지 않아도 된다"고 하셨지만, **무엇을 구현해야 하는지**의 기준이다.

| 주차 | 주제 | 핵심 구현/학습 |
|------|------|----------------|
| W1 | 프로젝트 이해·기본 개념 | PoC 목적/방향, 패킷분석·Proxy·HTTP/HTTPS·TLS·인증서·파일업로드 요청 구조 |
| W2 | 통신 구조·Proxy 동작 | 클라↔서버 흐름, **Explicit vs Transparent Proxy 차이**, Local Proxy 수신·중계 구조 |
| W3 | **Local Proxy 기본 구현** | TCP 프록시: 연결 수락 → 대상 서버 연결 → 요청/응답 중계 → 연결 종료, 테스트 |
| W4 | **HTTP 요청/응답 분석** | Method/URL/Host/Header/Content-Type/Body 파싱 + **로그 기록** |
| W5 | **TLS 암·복호화 구조 + 적용** | Root CA, Host별 Leaf 인증서, 클라-Proxy/Proxy-서버 두 TLS 세션, 복호화 환경 구성 |
| W6 | **HTTPS 트래픽 분석** | 복호화된 HTTPS의 URL/Header/Body 확인, "암호문이 Proxy 내부에서 평문으로" 검증(브라우저 대상) |
| W7 | **파일 업로드 행위 식별** | Multipart/Form-Data, Content-Disposition, 파일명, Content-Type, 파일 크기로 업로드 식별 |
| W8 | **업로드 파일 정보·바이너리 획득** | 파일명/확장자/MIME/크기/**Binary 추출**, 원본 파일과 일치 검증 |
| W9 | **파일 분석 + PoC 검증** | 파일 유형 분석, 확장자 검증, **파일 시그니처(매직넘버)** 확인, 여러 브라우저/AI Agent 환경 테스트, 성공/실패 정리 |
| W10 | **최종 보고서·발표** | 목적/구조/구현/테스트결과/한계/개선방향 정리 + 발표 |

→ **이번 과제의 본질 = W7~W9 "파일 업로드 식별·추출·분석"**. W3~W6은 그걸 위한 토대.

---

## B. 참고 목표 아키텍처 (NetFlow) — 더 큰 맥락 (인턴 범위 밖 포함)

책임님이 전에 진행한 구조. **WFP 포함**이라 현재 단계보다 넓다. 개념 참고용.

| 계층 | 역할 | 단계 |
|------|------|------|
| 커널 WFP driver | 프로세스/주소/포트 1차 정책 + transparent redirect | ⏳ **로컬 완성 후 다음 단계** |
| 리다이렉트 context | 원래 목적지 복원 | ⏳ (WFP 연계라 다음 단계) |
| 사용자 Local Proxy | HTTP/HTTPS 파싱 + L7 정책 | ✅ **지금 단계** |
| TLS MITM | 복호화 평문 분석 | ✅ (W5~W6) |
| Viewer | 세션/decision 관측 | △ (로그로 대체 가능) |

### 핵심 개념 (요지)
- **Explicit vs Transparent Proxy:**
  - Explicit = 앱/시스템이 "프록시 쓸게" 설정 → 프록시로 보냄. **(이번 과제 방식)**
  - Transparent = WFP가 앱 몰래 목적지를 프록시로 redirect. (NetFlow, 범위 밖)
- **TLS MITM:** HTTPS를 Client–Proxy / Proxy–Server **두 TLS 세션**으로 분리해 중간에서 평문 확인.
- **Root CA 필요 이유:** Proxy가 host별 leaf 인증서를 동적 생성 → 클라가 신뢰하려면
  **Proxy Root CA를 클라 신뢰 저장소에 등록**해야 함(안 하면 `NET::ERR_CERT_AUTHORITY_INVALID`).
- **Certificate Pinning:** 앱이 공개키/인증서를 고정 검증하면 OS가 Root CA 신뢰해도 **MITM 실패**(불가피 한계).
- **MITM 한계:** pinning, 별도 trust store, **QUIC/HTTP3(UDP)**, HTTP/2 multiplexing, 대용량 streaming.
  > ⚠️ 갱신(2026-07-13): **HTTP/2·QUIC(HTTP3)는 범위 안**(h2=Plan A→B, QUIC=Plan C). pinning은 여전히 불가·운영정책. 상세 `scope-and-protocol-coverage.md`.

---

## C. 본 과제의 진짜 목표 (회의 + W7~W9)

> **여러 AI 솔루션(ChatGPT/Gemini/네이버 등)이 각자 다른 프로토콜로 올리는
> "파일 업로드"를 식별하고, 파일 정보·바이너리를 추출·분석하는 것.**

회의 핵심:
- 제어 대상은 **AI 솔루션**. 서비스마다 프로토콜이 다르다.
- **파일 업로드 식별이 제일 관건이고, 쉽지 않다. 100%는 불가능**(변조/pinning/암호화 등).
- 그래서 **전 단계(통신 구조)를 잘 아는 게 중요.**

→ 결론: **연구 과제.** "완벽 탐지"가 아니라, 서비스별로
**"잡을 수 있다 / 이론상 못 잡는다"의 경계선을 긋고**(W9 성공/실패 정리),
가능한 범위에서 파일 메타·바이너리를 뽑아내는 것이 핵심 산출물.

### 왜 W7~W9가 진짜 어려운가 (책임님 조언)

> "프록시 구현은 AI 딸깍으로 틀 나온다. 시간이 많이 걸리는 건 바이너리를 어떻게 해석하는지다."

**어려운 이유**: 서비스마다 파일 업로드 포맷이 제각각이라 공식 문서가 없고,
직접 트래픽을 보면서 역으로 파악해야 한다.

| 서비스 유형 | 업로드 방식 | 파악 난이도 |
|------------|------------|------------|
| 표준 방식 | `multipart/form-data` (RFC 표준) | 낮음 (스펙 있음) |
| JSON 방식 | body에 base64 인코딩해서 전송 | 중간 |
| 자체 방식 | 서비스 전용 바이너리/API | 높음 (문서 없음, 트래픽만 보고 해석) |

**실제로 해야 하는 일 (W7~W9)**:
1. MITM으로 HTTPS 복호화 → 평문 HTTP body 확보
2. "이 바이트 패턴이 파일 업로드인가?" 를 트래픽 보며 직접 판단
3. "파일 바이너리가 body의 어디서 어디까지인가?" 경계를 코드로 파싱
4. 추출한 바이너리가 원본과 일치하는지 해시로 검증
5. 파일 시그니처(매직넘버)로 실제 파일 타입 확인

**Wireshark vs 우리 프록시**:
- Wireshark: 패킷 구조를 "보기만" 함. HTTPS는 암호화돼서 내용 못 봄.
- 우리 프록시: MITM으로 복호화해서 **평문을 코드로 처리** → 파일 추출까지.

**VS 디버거가 필요해지는 시점**: M6~M8 바이너리 파싱 단계.
`buffer[i]`에 뭐가 있는지 바이트 단위로 봐야 할 때, `printf`로는 한계가 있고
**VS 메모리 창(hex view) + 중단점** 조합이 압도적으로 편하다.
→ M1~M5는 VSCode로 충분, **M6부터 VS 디버거 쓸 준비** 해두면 좋다.

---

## D. 내 위치 / 해석

- 지금 만든 `proxy_relay`(턴제 릴레이) = **W3 Local Proxy의 학습용 미니 버전.**
- 실습 파일들은 **개념 익히기용**이고, 본 과제는 **제품 수준 실제 프록시**가 목표.
  (자세한 단계별 실행 계획은 → `execution-plan-to-mitm.md`)

```
proxy_relay 가 연습 중인 것       →  커리큘럼에서의 위치
recv/send HTTP 받기             →  W3 중계
parseHost (단순 strstr)         →  W4 견고한 HTTP 파싱으로 '재구현' 필요 (실습 수준 X)
요청 전달 + 응답 릴레이          →  W3 중계 + W5/W6 MITM 평문 분석의 기초
```

---

## E. 로드맵 (커리큘럼 정렬, WFP 제외)

```
[W1~W2] 개념 학습 (Proxy/HTTP/HTTPS/TLS/인증서/업로드 구조, Explicit vs Transparent)
   ↓
[W3] 제품 수준 Local Proxy (양방향 중계 + 연결 생명주기 + CONNECT 터널)   ← 지금 여기 근처
   ↓
[W4] 견고한 HTTP 요청/응답 파싱 + 로깅
   ↓
[W5] TLS MITM 환경 구성 (Root CA 생성/등록, host별 leaf, 두 세션)
   ↓
[W6] HTTPS 평문 분석 (브라우저 대상 검증)
   ↓
[W7] 파일 업로드 식별 (multipart/Content-Disposition/파일명/타입/크기)
   ↓
[W8] 파일 메타 + 바이너리 추출 (원본 일치 검증)
   ↓
[W9] 파일 분석(시그니처 등) + 여러 환경 PoC 검증 (성공/실패 정리)
   ↓
[W10] 최종 보고서 + 발표
   ↓
[그 다음 단계 — 로컬 프록시 전부 완성 후] WFP 커널 드라이버 + transparent redirect
   (조건: 로컬이 다 완성된 이후에 진행. 제외가 아니라 '나중에')
```

---

## F. 현실적 스코프

- 목표 = **완벽 탐지 X**, "어디까지 되고 어디부터 안 되는지" **경계 긋기**(W9).
- **타깃 2~3개 AI 서비스부터** 좁혀서 시작.
- 매 단계 = **동작 코드 + 설명 + 테스트결과/한계** 세트 (W10 보고서로 수렴).
- 트래픽 유도는 **Explicit Proxy**(브라우저 프록시 설정 / curl -x) — WFP 없이 진행.

---

## 관련 문서
- 단계별 실행 계획(주차 매핑·마일스톤): `execution-plan-to-mitm.md`
- 다음 AI 인계: `ai-handoff.md`
- 개념 노트: `socket-buffer-and-string.md`, `step3-host-parsing-and-relay.md`
- C 기초 실습: `../c_basics_lab/`
