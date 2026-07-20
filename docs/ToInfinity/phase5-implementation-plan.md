# Phase 5: 트래픽 분석 및 파일 업로드 추출 (AI 서비스별 모듈화 + 압축/검증 처리)

이 문서는 `research_areas.md`와 `project-goal-and-roadmap.md`에서 정의한 전체 요구사항을 모두 수용한 분석 엔진(`TrafficAnalyzer`) 구현 계획입니다. 사용자님의 지적에 따라 누락되었던 **압축 해제(1-B)**, **해시 검증(W8)**, **매직넘버 확인(W9)** 요소를 모두 포함시켰습니다.

## User Review Required

> [!IMPORTANT]
> 1-B(Content-Encoding)에 대한 가장 효율적인 접근 방식을 제안합니다.
> 당장 C++에서 zlib이나 brotli 압축 해제 라이브러리를 연동하는 것은 오버헤드가 큽니다. 대신 **프록시(엔진)가 클라이언트의 요청 헤더에서 `Accept-Encoding`을 강제로 지워버리는 방법(Downgrade)**을 사용하면, 서버가 압축하지 않은 평문으로 응답하게 됩니다. 이 꼼수(?)를 먼저 적용하는 것이 어떨까요?

## Proposed Changes

### 1. Inspector/TrafficAnalyzer.h & cpp (라우터 및 파서)
- **트래픽 라우터:** `Host`, `URL`, `Content-Type`을 기반으로 `ChatGPTParser`, `StandardMultipartParser` 등으로 트래픽을 분류합니다.
- **표준 파서 구현:** `boundary` 파싱, `filename` 추출, 바이너리 분리 로직을 구현합니다.
- **[추가] W8 해시 검증:** 추출된 바이너리 데이터를 디스크(`captured_files/`)에 저장함과 동시에, **SHA-256 또는 기본 해시 함수**를 돌려서 로그에 출력합니다. (원본 파일과 100% 일치하는지 증명하기 위함)
- **[추가] W9 매직넘버 검증:** 추출된 파일의 첫 4~8바이트(Magic Number)를 읽어서, 헤더의 MIME 타입(`application/pdf` 등)과 실제 파일 포맷(예: `%PDF-`)이 일치하는지 교차 검증합니다.

### 2. Protocol/Http1Engine & Http2Engine 연동 (압축 헤더 조작)
- **[추가] 1-B 압축 회피:** 클라이언트가 서버로 보내는 요청 헤더(`headers` 맵)에서 `Accept-Encoding: gzip, deflate, br` 헤더를 찾아내어 **삭제하거나 `identity`로 덮어씁니다.** 이렇게 하면 서버가 무조건 평문으로 응답하므로, 응답 데이터(Response Body)도 `TrafficAnalyzer`가 쉽게 파싱할 수 있게 됩니다.
- 요청/응답 헤더와 완성된 Body를 `TrafficAnalyzer`로 안정적으로 넘겨줍니다.

## Verification Plan

### 수동 테스트
- 프록시를 띄우고 테스트용 PDF 파일을 업로드합니다.
- 콘솔에 다음 로그가 모두 정상적으로 찍히는지 확인합니다:
  1. `[Router] 표준 멀티파트 파서로 라우팅됨`
  2. `[Parser] 파일명: test.pdf, 크기: 1042 bytes 추출 완료`
  3. `[Verifier] 매직넘버 일치 확인 (%PDF- -> PDF 파일 맞음)`
  4. `[Verifier] 추출된 파일 해시: A1B2C3D4... (원본과 비교 요망)`
- 응답 트래픽에서도 `Content-Encoding: gzip`이 사라지고 평문으로 잘 들어오는지(압축 회피 성공 여부) 확인합니다.
