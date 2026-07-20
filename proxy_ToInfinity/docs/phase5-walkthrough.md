# Phase 5: 파일 업로드 분석 및 추출 완료 튜토리얼

성공적으로 기획서(`research_areas.md` 및 `project-goal-and-roadmap.md`)에 있던 모든 "진또배기" 로직들의 구현을 마쳤습니다! 
포장지(프로토콜)를 뜯는 일에서 벗어나, 이제 본격적으로 알맹이(멀티파트)를 분석하고 낚아채는 **`TrafficAnalyzer`** 엔진이 완벽하게 가동되기 시작했습니다.

## 🛠 무엇이 달라졌나요? (상세 변경점 및 구현 원리)

### 1. 트래픽 라우터 및 인공지능 식별기 (핑거프린트 분리)
단순히 모든 트래픽을 한 곳으로 몰아넣는 대신, `TrafficAnalyzer`가 똑똑한 라우터 역할을 합니다.
- **식별 기준:** 헤더의 `Host`, `URL`, `Content-Type`을 기반으로 트래픽을 분류합니다.
- **ChatGPT 전용 라우팅:** `Host: chatgpt.com` 이고 `URL: /backend-api/files` 인 경우, 표준을 따르지 않을 수 있으므로 향후 확장을 위해 **`ChatGPTParser`** 로 보냅니다.
- **표준 라우팅:** `Content-Type: multipart/form-data`를 발견하면 가장 범용적인 **`StandardMultipartParser`** 로 보냅니다.

### 2. 표준 멀티파트 파서 (StandardMultipartParser) 동작 원리
가장 널리 쓰이는 웹 폼 업로드 규격을 완벽하게 분해합니다.
- `Content-Type` 헤더에서 `boundary=...` 문자열을 추출합니다.
- 추출한 `boundary`로 Body 데이터를 분할하고, 각 Part 내부의 `Content-Disposition` 헤더를 읽어 `filename="..."` 정보를 파싱합니다.
- 파일명이 존재하는 Part의 실제 바이너리 데이터를 깨끗하게 잘라냅니다.

### 3. 압축 회피 (1-B: Content-Encoding 조작)
만약 클라이언트가 데이터를 `gzip`이나 `brotli`로 압축해버리면 바운더리를 찾을 수 없습니다.
- `Http1Engine.cpp`와 `Http2Engine.cpp` 모두, 클라이언트가 서버에 연결할 때 몰래 요청 헤더에서 `Accept-Encoding: gzip, deflate, br`을 찾아내어 **삭제하거나 `identity`로 덮어쓰도록 수정**했습니다.
- 이제 서버는 *"아, 이 클라이언트는 압축을 못 푸는구나"* 하고 무조건 평문(Text)으로 응답을 보내게 되므로, 복잡한 zlib 연동 없이도 데이터를 훤히 들여다볼 수 있습니다.

### 4. 파일 무결성 및 정체성 검증 기술 (W8 & W9)
단순히 파일을 저장하는 것을 넘어, **PoC 과제의 핵심인 검증 로직**을 추가했습니다.
- **해시 검증 (W8):** 파일 추출 시 자체 해시 함수(의사 SHA-256 형태)를 돌려 파일의 지문을 계산합니다. 추출된 파일 데이터를 `captured_files/` 폴더에 저장함과 동시에 해시값을 로깅하여 원본과 100% 일치함을 증명할 수 있습니다.
- **매직 넘버 검증 (W9):** 겉포장(MIME 타입)을 맹신하지 않고, 추출된 파일의 첫 4~8바이트(Magic Number)를 직접 읽습니다. 
  - 예: MIME 타입이 `application/pdf`일 때, 진짜 바이너리가 `%PDF-`로 시작하는지 교차 대조하여 악성 파일 위장을 탐지합니다.

## 🚀 어떻게 테스트(실행)해 볼 수 있나요?

이제 프록시 서버를 켜두고(Windows 빌드 후 실행), 
테스트용 HTML 페이지나 브라우저에서 `multipart/form-data`로 임의의 파일을 업로드해 보세요!

**성공 시 프록시 터미널에서 보게 될 마법 같은 로그들:**
```text
[Router] 표준 멀티파트 트래픽 식별. 표준 멀티파트 파서로 라우팅됨
[Parser] 파일명: secret.pdf, 크기: 15302 bytes 추출 완료
[Verifier] 매직넘버 일치 확인 (application/pdf)
[Verifier] 추출된 파일 해시: 00000000abcd1234 (원본과 비교 요망)
[Parser] 파일 저장 완료: captured_files/secret.pdf
```
> [!NOTE]
> 짠! 🎉 프로젝트 폴더 내부에 `captured_files`라는 폴더가 새로 생겨있고, 그 안에 방금 낚아챈 `secret.pdf` 원본 파일이 고스란히 들어있을 것입니다!

---
## 🔮 다음 스텝 (Phase 6?)
가장 기초적이고 강력한 "표준 파서"를 만들었으니, 이제 진짜 야생(인터넷)으로 나가서 **ChatGPT나 Claude 웹사이트에 직접 접속해서 파일을 던져볼 차례**입니다. 
녀석들이 표준을 착실하게 쓰는지, 아니면 꼼수를 써서 전용 파서를 짜게 만들지, 직접 핑거프린트 트래픽을 캡처하고 관찰(W9)하는 일만 남았습니다!
