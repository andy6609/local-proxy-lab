# M4/M5 노트 — TLS MITM (proxy_v4): 된 것 + 안 된 것

> 목적: v4 가 어디까지 했고(복호화·평문 분석), 무엇이 아직 PoC 라 안 됐는지 구분.
> (셋업/빌드 = `m4-mitm-setup.md`, 개념 흐름 = `m3-notes.md §5`, 코드 = `../proxy_v4/proxy_v4.cpp`)
> (이전 단계: `m1-tradeoffs.md`, `m2-notes.md`, `m3-notes.md`)

---

## 1. 한 줄 요약

**v4 = HTTPS 를 복호화해서 평문 HTTP 로 분석하는 단계.** (W5 MITM 기초 + W6 평문 분석)
- v3: CONNECT → 암호 바이트 그대로 통과 (내용 못 봄)
- v4: CONNECT → **내가 양쪽 TLS 를 끊어** 복호화 → M2 파서로 분석 → 재암호화 전달

검증됨(curl): `MITM GET httpbin.org/get -> 200` 처럼 **평문 method/URL/status 가 보임.**

---

## 2. ✅ 실제로 된 것 (검증 완료)

| 항목 | 상태 |
|---|---|
| Root CA 로 host 별 leaf 인증서 **동적 생성·캐시** | ✅ (M5 의 동적 인증서) |
| 브라우저측 TLS 서버役 handshake (`SSL_accept`) | ✅ |
| 서버측 TLS 클라役 handshake (`SSL_connect`, SNI) | ✅ |
| **HTTPS 복호화 → 평문 HTTP 분석** | ✅ (curl `--ssl-no-revoke`) |
| 평문 HTTP(M2 경로)도 그대로 동작 | ✅ |
| Stream 추상화로 M2 파서를 평문/TLS 양쪽 재사용 | ✅ |

> **핵심:** 복호화 엔진 자체는 멀쩡하다. 아래 한계는 대부분 '복호화 다음' 또는 '특정 사이트' 문제.

---

## 3. ⛔ 아직 구현 안 된 것 (= 보고서의 "한계" 섹션)

### (A) HTTP/2 미지원  ← 실브라우저로 가면 제일 먼저 막히는 것
- **복호화는 된다.** 푼 다음 나온 게 HTTP/1.1 텍스트가 아니라 **HTTP/2 바이너리 프레이밍**이라
  우리 M2 파서가 못 읽는다. → 복호화 문제 아님, **파싱 문제.**
- curl 은 기본이 HTTP/1.1 이라 통과했지만, **크롬/엣지는 https 에 기본 h2** 를 쓴다.
  → 지금 v4 를 실브라우저로 붙이면 TLS 는 풀리는데 안에서 h2 가 나와 깨진다.
- **해결안 2가지(아직 안 함):**
  1. handshake 때 ALPN 으로 "h2 안 함, http/1.1 로"라고 협상해 브라우저를 1.1 로 내림 (PoC 흔함, 작음)
  2. HTTP/2 프레이밍 파서를 별도 구현 (일 큼)

### (B) upstream(진짜 서버) 인증서 검증 꺼둠
- 현재 `SSL_VERIFY_NONE`. "안 되는" 게 아니라 **보안 약점** — 가짜/만료 인증서 서버에도 그냥 붙는다.
- 제품은 시스템 CA 번들로 `SSL_VERIFY_PEER` + 실패 시 차단/기록 필수.
  (코드에 `SSL_set1_host` 는 이미 세팅돼 있어 verify 만 켜면 호스트 매칭됨)

### (C) 인증서 피닝 / HSTS 사이트 → 원리적 복호화 불가
- 구글 일부·뱅킹앱 등은 "내가 아는 인증서 아니면 거부"(피닝)라 우리 가짜 leaf 를 거부.
  → 클라측 handshake 자체가 실패. **MITM 의 불가피한 한계.**
- 제품은 이런 도메인을 **raw 터널 fallback(v3 처럼)** 또는 bypass 목록으로 처리해야 함. (아직 없음)

### (D) 기타 미구현 (코드 맨 아래 한계 블록에도 기록)
- leaf 키 1개 공유 + SSL_CTX host 별 캐시가 메모리에 계속 쌓임 (PoC 수준, 정리 없음).
- 동시성: 연결당 스레드 (대규모는 IOCP 가 맞음).
- (M2/M3 승계) absolute-form URI 정규화, hop-by-hop 헤더 처리, Expect:100-continue,
  IPv6 host:port 미처리.
- 실브라우저(크롬/엣지/Firefox) 테스트 미수행 — 현재 curl 만.

---

## 4. 🟡 테스트 시 알아야 할 환경 이슈 (구현 한계는 아님)

| 이슈 | 이유 / 대응 |
|---|---|
| curl `CRYPT_E_NO_REVOCATION_CHECK (35)` | 우리 leaf 에 CRL/OCSP 없음 → schannel 폐기검사 실패. `--ssl-no-revoke` 로 우회 |
| `no OPENSSL_Applink` 크래시 | (해결됨) `fopen` 대신 `BIO_new_file` 사용 |
| `bind failed: 10013` | 이전 프록시가 18080 점유 → 그 프로세스 종료 |

---

## 5. 이 단계가 파일 업로드 탐지(M6~M7)로 어떻게 이어지나

- 이제 **복호화된 평문**이 `proxyExchange` 를 통과한다.
- 그 안에서 요청을 더 들여다보면:
  - `Content-Type: multipart/form-data` → "이거 파일 업로드 요청"
  - `Content-Disposition: ...; filename="..."` → 파일 이름
  - body → 파일 바이너리
- 즉 **MITM 으로 길은 다 뚫렸고**, 그 평문 위에서 식별→추출→분석을 더하는 게 본 과제(M6~M8).

```
v4: CONNECT -> [TLS 복호화] -> 평문 -> (method/URL/status 분석)         ← 지금 여기
M6: 평문 위에서 multipart/Content-Disposition 식별 -> 업로드 탐지
M7: body 에서 파일 바이너리 추출 -> 해시 검증
```

---

## 6. 권장 다음 순서

1. **(A) ALPN http/1.1 강제** 추가 → 실제 크롬/엣지로 복호화 검증 (W6 마무리 + h2 한계 직접 확인)
2. M6: 복호화 평문에서 업로드 식별 (multipart 판별, 서비스별 지문표)

---

## 관련 문서
- 셋업/빌드: `m4-mitm-setup.md`
- 실행 계획: `execution-plan-to-mitm.md` (M4/M5 정의)
- 이전 단계: `m1-tradeoffs.md`, `m2-notes.md`, `m3-notes.md`
- 코드: `../proxy_v4/proxy_v4.cpp` (맨 위 설계 주석 + 맨 아래 "한계" 블록)
