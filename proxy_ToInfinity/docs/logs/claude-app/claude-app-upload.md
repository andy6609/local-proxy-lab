# Claude 데스크톱 앱 업로드 캡처 실측 기록 (DLP 우회 취약점 발견)

> 캡처 일시: 2026-07-22
> 대상 서비스: `Claude Desktop App for Mac` (프록시 강제 후킹)
> 업로드 파일: `.docx` 파일

이 문서는 데스크톱 전용 앱을 통해 파일을 업로드할 때 프록시에 어떤 현상이 발생하는지, 그리고 웹 브라우저 통신과 어떤 치명적인 차이점이 있는지를 기록합니다.

---

## 1. 프록시에 찍힌 터미널 로그 분석 (결정적 차이)

데스크톱 앱에서 `.docx` 파일을 드래그하여 업로드하고 전송했을 때, 프록시는 `multipart/form-data` 요청을 **단 한 건도 발견하지 못했습니다.** 대신, 아래와 같이 비정상적으로 거대한 JSON 페이로드를 가진 API 요청이 포착되었습니다.

```text
[INFO]  [Observe] POST claude.ai/api/organizations/efeb8236-bb4a-47f7-9eb0-d4837a8dda96/chat_conversations/f596bb86-15b2-434c-9605-4dce1ea81525/completion  ct=[application/json]  bodylen=32595  head={"prompt":"","timezone":"Europe/London","locale"
```

### 🔍 웹(Web) vs 앱(App) 차이점 요약
- **Claude Web:** 파일을 먼저 `multipart/form-data` 전용 엔드포인트(`/upload-file`)로 전송하여 고유 ID를 받은 후, 그 ID만 채팅(`completion`)에 텍스트로 보냅니다.
- **Claude App:** 전용 업로드 엔드포인트를 쓰지 않습니다. 앱 내부(로컬)에서 `.docx` 파일을 텍스트나 Base64 형태로 완전히 파싱한 다음, 채팅 프롬프트 JSON 바디(`completion`) 안에 한꺼번에 욱여넣어 무려 **32KB**짜리 거대한 JSON 요청 한 방으로 서버에 전송해 버립니다.

## 2. 사내 보안(DLP) 시스템 관점에서의 치명적 위협 (Bypass)

이 현상은 기업 보안망에서 엄청난 취약점(Blind Spot)을 의미합니다.
대부분의 기업용 네트워크 DLP(Data Loss Prevention) 장비나 룰셋은 **"파일 업로드 = `multipart/form-data` 패킷"**이라는 고정관념에 맞춰 설계되어 있습니다.

만약 사내 직원이 브라우저 대신 **Claude 데스크톱 앱을 설치해서 기밀 문서를 올린다면, DLP 시스템은 이를 단순한 '채팅 텍스트(JSON) 전송'으로 착각하고 아무런 제재 없이 통과**시켜 버립니다. (100% 우회 가능)

## 3. ToInfinity 프록시의 향후 대응 과제
기존에 만든 `StandardMultipartParser`는 `multipart` 헤더가 없으면 작동하지 않습니다. 따라서 Claude 앱과 같이 JSON에 파일을 통째로 말아버리는 신종 수법을 차단하려면 다음 기능이 추가되어야 합니다.

- **JSON 바디 딥 인스펙션(Deep Inspection) 파서 개발:** `application/json` 타입이면서 `bodylen`이 비정상적으로 큰(예: 10KB 이상) `completion` API 요청을 낚아채서, JSON 구조 내부의 `attachments`나 `files` 배열을 뜯어내어 파일 해시를 추출하는 전용 파서 모듈(`ClaudeJsonParser`)이 필요합니다.
