/*
============================================================
 C 기초 2단계: 함수에 넘기기 (값 vs 주소) + 배열 넘기기 + const
============================================================

1단계에서 배운 것: 변수 / 주소 / 포인터 / 배열
이번엔 그걸 '함수에 넘길 때' 무슨 일이 일어나는지 본다.
(우리 proxy_relay 가 헷갈렸던 진짜 이유가 여기 다 있음)

------------------------------------------------------------
[핵심 1] 인자는 '위치(순서)'로 짝지어진다  (이름은 달라도 됨!)
    부를 때 1번째 -> 받을 때 1번째 칸으로 들어감.
        add(3, 5)  ->  int add(int a, int b)  ->  a=3, b=5
    => 그래서 parseHost(buffer, ...) 의 buffer 가
       parseHost(const char* request, ...) 의 request 로 들어간 거임.
       이름이 buffer/request 로 달라도 '첫 번째 자리'라서 연결됨.

[핵심 2] (A) 값으로 넘기면 '복사본'이 간다 -> 원본 안 바뀜
         (B) 원본을 바꾸고 싶으면 '주소(&)'를 넘긴다
    => 우리 프록시에서 getaddrinfo(..., &serverInfo) 한 게 (B) 원리.
       "원본을 채워줘" 라서 주소를 넘긴 것.

[핵심 3] (C) 배열을 함수에 넘기면 -> '자동으로 포인터(주소)로' 변신해서 간다
    - 배열 전체를 복사하는 게 아니라 '시작 주소'만 넘어감 (그래서 빠름)
    - 대신 '길이 정보'가 사라짐! -> 길이를 인자로 따로 넘겨야 함
    - 함수 안에서 배열을 바꾸면 -> 원본도 바뀜 (주소를 받았으니까)
    => 이게 1단계의 "배열 이름 = 첫 원소 주소" 가 실제로 쓰이는 곳.

[const 는?]
    const char* p  ->  "p로는 그 내용을 못 바꾼다(읽기 전용)"
    읽기만 할 거면 const 붙이는 게 안전 + "나 안 바꿀게" 의도 표현.
    (문자열 리터럴 "GET..." 이 읽기 전용이라 const char* 로 받았던 것)
------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>

// (A) 값으로 받음 -> 복사본 -> 원본 안 바뀜
void tryChangeByValue(int n) {
    n = 999;  // 복사본만 바뀜 (밖의 원본과 무관)
}

// (B) 주소로 받음 -> 원본을 직접 바꿈
void changeByAddress(int* n) {
    *n = 999;  // n이 가리키는 '원본'에 999를 넣음
}

// (C) 배열을 받음 (사실은 포인터로 받는 것) + 길이를 따로 받아야 함
//     'int arr[]' 라고 써도 실제론 'int* arr' 과 같음. 길이정보가 없으니 len 을 따로 받음.
void printArray(int arr[], int len) {
    for (int i = 0; i < len; i++) {
        printf("   arr[%d] = %d\n", i, arr[i]);
    }
}

// 배열 안에서 바꾸면 원본도 바뀜 (주소를 받았으니까)
void doubleFirst(int* arr) {
    arr[0] = arr[0] * 2;
}

// const: 읽기만 함 (못 바꿈). 인자 이름을 일부러 'request' 로 -> 우리 parseHost 랑 같은 느낌
void onlyRead(const char* request) {
    printf("   읽기 전용으로 받음: %s\n", request);
    // request[0] = 'X';  // <- 이 줄 주석 풀면 '컴파일 에러'! const 라서 내용 수정 불가
}

int main(void) {
    // (A) 값으로 넘기기
    int a = 10;
    tryChangeByValue(a);
    printf("(A) 값으로 넘긴 뒤 a = %d   <- 안 바뀜 (복사본만 바뀜)\n", a);

    // (B) 주소로 넘기기
    int b = 10;
    changeByAddress(&b);   // &b = b의 주소를 넘김
    printf("(B) 주소로 넘긴 뒤 b = %d   <- 바뀜! (원본을 직접 수정)\n", b);

    // (C) 배열 넘기기
    int nums[3] = { 1, 2, 3 };
    printf("(C) 배열을 함수에 넘겨 출력 (배열 = 주소로 변신, 길이 3 따로 넘김):\n");
    printArray(nums, 3);

    doubleFirst(nums);     // 배열 안에서 바꾸면
    printf("    doubleFirst 후 nums[0] = %d   <- 원본 바뀜! (주소를 넘겼으니까)\n", nums[0]);

    // const 읽기 전용
    char msg[] = "hello";
    onlyRead(msg);   // msg(배열) -> const char* 로 받음 (자동으로 포인터 변환)

    return 0;
}

/*
[2단계 요약 — 우리 프록시랑 연결]
 - 인자는 '위치'로 짝지어짐  => buffer(1번째) -> request(1번째). 이름 달라도 OK.
 - 값 넘기기  = 복사본 (원본 안 바뀜)
 - 주소(&) 넘기기 = 원본 바뀜  => getaddrinfo(..., &serverInfo) 가 이거
 - 배열 넘기기 = 자동으로 포인터(주소)로  => 그래서 길이(outHostSize)를 따로 넘김
 - const char* = 읽기 전용  => 문자열 리터럴/요청을 '읽기만' 할 때
 다음 단계(3)에서 이걸 다 합쳐서 parseHost 미니 버전을 만들어봄.
*/
