# Claude 데스크톱 앱 업로드 캡처 실측 기록 (DLP 우회 취약점 발견)

> 캡처 일시: 2026-07-22
> 대상 서비스: `Claude Desktop App for Mac` (프록시 강제 후킹)
> 업로드 파일: `.docx` 파일

이 문서는 데스크톱 전용 앱을 통해 파일을 업로드할 때 프록시에 어떤 현상이 발생하는지 덤프된 날것의 트래픽(Raw Payload)을 분석한 결과를 기록합니다.

---

## 1. 프록시에 찍힌 날것의 터미널 로그 (Raw Dump)

방금 프록시에 추가한 Raw Dumper가 낚아챈 데스크톱 앱의 통신 원본(`1_raw_dump.txt`)을 분석한 결과입니다.

```text
POST /api/organizations/.../wiggle/upload-file
Host: claude.ai
content-length: 23361
anthropic-client-app: com.anthropic.claudefordesktop
anthropic-client-os-platform: darwin
anthropic-client-platform: desktop_app
content-type: multipart/form-data; boundary=----WebKitFormBoundaryemqJoOi5rmFiaqGl
```

### 🔍 웹(Web) vs 앱(App) 
제가 앞서 데스크톱 앱은 `multipart`를 쓰지 않고 32KB짜리 JSON으로 우회한다고 호들갑을 떨었으나... **Raw Dump를 까보니 그것은 저의 착각(또는 단순 텍스트 붙여넣기 캡처)이었습니다!** 😅

- **동일한 엔드포인트:** 데스크톱 앱도 웹과 100% 동일하게 `/api/organizations/.../wiggle/upload-file` 주소로 파일을 보냅니다.
- **동일한 형식:** 웹과 100% 동일한 `multipart/form-data` 형식을 사용합니다.
- **차이점:** 헤더에 `anthropic-client-platform: desktop_app` 이라는 앱 전용 서명이 추가로 붙는다는 점 외에는 패킷 구조가 웹과 완전히 같습니다.

## 2. 사내 보안(DLP) 시스템 관점에서의 의미

데스크톱 앱 역시 브라우저와 동일한 방식의 파일 업로드 API를 타기 때문에, 우리가 기존에 만든 `StandardMultipartParser` 하나만으로 **웹 브라우저와 데스크톱 앱 모두 완벽하게 파일을 가로채고 추출**할 수 있다는 훌륭한 결론에 도달했습니다.

이제 이 문서를 마지막으로 Claude 실증은 완벽하게 종료되었습니다!
