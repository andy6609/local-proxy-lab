/*
============================================================
 C 기초 3단계: 다 엮어보기 — 우리 proxy_relay 의 parseHost 미니 버전
============================================================

1단계: 포인터 / 배열  (배열 이름 = 첫 원소 주소)
2단계: 함수로 넘기기(값/주소), 배열->포인터 변신, const, 위치로 짝짓기
이번엔 그걸 '전부' 합쳐서, 우리 프록시의 parseHost 가
왜 그렇게 생겼는지 직접 만들어보며 이해한다.

------------------------------------------------------------
[이번 핵심 패턴: '출력 파라미터(output parameter)']

  함수가 결과를 'return' 으로 돌려주는 대신,
  부르는 쪽이 '빈 그릇(배열)'을 넘겨주면 -> 함수가 그 그릇을 채워준다.

  왜 이렇게 하냐?
   - 문자열(여러 글자)은 return 하나로 깔끔히 돌려주기가 번거로워.
   - 그래서 "여기 빈 그릇 줄게, 네가 채워줘" 방식을 자주 씀.
   - 반환값(return)은 '성공/실패(true/false)' 신호로만 쓰고,
     진짜 결과(뽑은 문자열)는 넘겨준 그릇에 채워줌.

  이게 우리 parseHost(buffer, host, sizeof(host)) 랑 '완전히 똑같은' 구조!

[개념 총정리 — 어디서 뭐가 쓰이나]
  - text     : 읽기만 할 거라 const char*        (2단계: const)
  - out      : 결과 채울 '빈 그릇'. 배열을 넘기면 포인터로 받음  (2단계: 배열->포인터)
  - outSize  : 배열은 길이정보가 사라지니까 크기를 따로 넘김     (2단계: (C))
  - return bool : 성공/실패 신호. 부르는 쪽이 if 로 확인          (2단계: 위치로 받기)
  - strstr   : 문자열 속 문자열 찾기 (C 표준 <string.h> 함수)
  - 포인터 p 를 한 칸씩 밀며 읽기 (*p, p++)                       (1단계: 포인터)
------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>   // C에서 bool/true/false 쓰려면 필요 (C++은 기본 제공이라 안 써도 됨)

// 우리 proxy_relay 의 parseHost 와 사실상 동일한 '미니 버전'.
//   text 안에서 "Name:" 뒤의 값을 뽑아 out 에 담는다.
//   성공하면 true, 못 찾으면 false.
bool extractValue(const char* text, char* out, int outSize) {
    // 1. text 안에서 "Name:" 위치 찾기 (strstr: 큰 문자열 속에서 특정 문자열 찾아 그 주소 반환, 없으면 NULL)
    const char* p = strstr(text, "Name:");
    if (p == NULL) return false;   // 못 찾으면 실패 신호

    p += 5;                  // "Name:" 5글자만큼 포인터를 앞으로 밀어 -> 값 바로 앞으로
    while (*p == ' ') p++;   // 콜론 뒤 공백이 있으면 건너뜀

    // 2. 줄 끝(\n) 또는 문자열 끝(\0) 전까지 한 글자씩 out 에 복사
    int i = 0;
    while (*p != '\n' && *p != '\0' && i < outSize - 1) {
        out[i] = *p;   // out(= 부르는 쪽이 넘긴 그릇)에 '직접' 채움 -> 원본 그릇이 채워짐
        i++;
        p++;
    }
    out[i] = '\0';     // 문자열 끝 표시 (이게 있어야 %s 가 안전)
    return true;       // 성공 신호
}

int main(void) {
    // 이게 우리 'buffer'(요청 전체) 같은 거 (읽기만 할 거라 const)
    const char* request = "GET / HTTP/1.1\nName: httpbin.org\nOther: 123\n";

    // 이게 우리 'host[256]' 같은 '빈 그릇'
    char value[256];

    // ↓↓↓ 우리 HandleClient 의  if(!parseHost(buffer, host, sizeof(host)))  랑 구조가 똑같음 ↓↓↓
    if (extractValue(request, value, sizeof(value))) {
        // 여기 도달하면 value 그릇엔 이미 결과가 채워져 있음
        printf("뽑기 성공! value = %s\n", value);   // -> httpbin.org
    }
    else {
        printf("Name 헤더를 못 찾음\n");
    }

    return 0;
}

/*
[3단계 = 우리 proxy_relay 대응표]

   이 파일 (연습)                         proxy_relay.cpp (실전)
   --------------------------------       --------------------------------
   extractValue(text, out, outSize)   <-> parseHost(request, outHost, outHostSize)
   request (const char*)              <-> buffer 를 받은 request (const char*)
   value[256] (빈 그릇)               <-> host[256] (빈 그릇)
   if (extractValue(...))             <-> if (!parseHost(...))
   strstr(text, "Name:")              <-> strstr(request, "Host:")
   out[i] = *p; ... out[i]='\0';      <-> outHost[i] = *p; ... outHost[i]='\0';

[한 줄 결론]
   "함수에 빈 그릇(배열)을 넘기면 -> 함수가 그 그릇을 채워서 돌려준다."
   parseHost 가 host 를 채워준 게 바로 이 패턴이고,
   이게 가능한 건 1~2단계(배열=주소, 주소 넘기면 원본 수정) 덕분이다.
*/
