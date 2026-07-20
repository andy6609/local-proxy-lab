# HTTP/2 PROTOCOL_ERROR (RST_STREAM err=1) 버그 해결 기록

## 1. 문제 증상
`proxy_plan_B.cpp`를 사용하여 브라우저 트래픽을 가로채고 HTTP/2 통신을 시도했을 때, 거의 모든 HTTPS 사이트(claude.ai, wikipedia.org 등)에서 페이지가 로딩되지 않고 **`ERR_HTTP2_PROTOCOL_ERROR`** 에러를 뱉는 현상이 발생했습니다.

터미널 계측 결과:
- 클라이언트(브라우저)에서 온 요청은 프록시가 정상적으로 수신하여 nghttp2를 통해 Upstream 서버로 `submit_request`를 성공했습니다.
- 그러나 Upstream 서버가 요청을 받자마자 **즉시 `RST_STREAM` 프레임 (에러코드 1: PROTOCOL_ERROR)** 을 반환하며 해당 스트림을 강제로 끊어버렸습니다.
- 무-body(GET) 요청에서 특히 이 현상이 두드러졌습니다.

## 2. 원인 분석
초기에는 `nghttp2_submit_request`에 전달되는 데이터 제공자(Data Provider)나 END_STREAM 플래그의 문제로 의심했습니다. 그러나 진짜 원인은 C++의 고전적인 **임시 객체 생명주기(Dangling Pointer)** 버그였습니다.

문제가 된 코드는 `mkNv` 헬퍼 함수와 호출부였습니다.

```cpp
// [기존 코드 - 문제점]
static nghttp2_nv mkNv(const std::string& name, const std::string& value) {
    nghttp2_nv nv;
    nv.name = (uint8_t*)name.data(); 
    nv.namelen = name.size();
    nv.value = (uint8_t*)value.data(); 
    nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NONE; // nghttp2가 나중에 복사함
    return nv;
}

// 호출부
nva.push_back(mkNv(":method", s->method));
```

**버그 발생 과정:**
1. `mkNv`의 첫 번째 인자는 `const std::string&` 타입입니다.
2. 호출할 때 `":method"`라는 C-스타일 문자열 리터럴을 전달하면, C++ 컴파일러는 암시적으로 `std::string` **임시 객체**를 생성합니다.
3. `mkNv` 함수는 이 임시 객체의 내부 버퍼 주소(`.data()`)를 뽑아서 `nghttp2_nv` 구조체에 저장합니다.
4. `push_back`이 끝나고 세미콜론(`;`)을 만나는 순간, **임시 객체가 소멸(Destroy)** 됩니다.
5. 결과적으로 `nva` 배열 안에 들어있는 포인터들은 **쓰레기 메모리(Dangling Pointer)** 를 가리키게 됩니다.
6. 이후 `nghttp2_submit_request`가 이 배열을 읽어 HTTP/2 HEADERS 프레임을 만들 때, 서버는 `:method`가 아닌 쓰레기 문자열을 받게 됩니다.
7. HTTP/2 스펙상 `:method`, `:scheme`, `:path`, `:authority` 같은 필수 가상(Pseudo) 헤더가 올바르게 존재하지 않으면 서버는 즉각 **PROTOCOL_ERROR** 로 연결을 끊습니다.

## 3. 해결 방안
`nghttp2_nv`를 생성할 때 동적 할당이나 불필요한 임시 객체 생성을 막기 위해, 리터럴(Static String)과 수명이 보장된 변수를 직접 가리키도록 구조를 변경했습니다.

```cpp
// [해결된 코드 - 매크로를 이용한 안전한 리터럴 주소 참조]
#define MAKE_NV(NAME, VALUE) \
    {(uint8_t*)(NAME), (uint8_t*)(VALUE).c_str(), sizeof(NAME) - 1, (VALUE).size(), NGHTTP2_NV_FLAG_NONE}

// 호출부
nva.push_back(MAKE_NV(":method", s->method));
```

이렇게 하면 `NAME` 자리에 들어가는 `":method"`는 컴파일 타임 문자열 리터럴이므로 생명주기가 영구적이며, `VALUE` 자리에 들어가는 `s->method`는 `H2Stream` 객체의 멤버이므로 `submit_request`가 완료될 때까지 안전하게 메모리에 살아있게 됩니다.
