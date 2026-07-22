# Mac(POSIX) 포팅 트러블슈팅 기록

> Windows(MSVC) 환경에서 개발된 `proxy_ToInfinity`를 Mac(POSIX) 환경으로 크로스 컴파일 및 실행하면서 발생한 치명적인 플랫폼 종속 버그와 해결 과정을 기록한다. (발생일: 2026-07-22)

## 1. `select()` 함수의 `nfds` 파라미터 차이 버그

### ❌ 현상
Mac에서 프록시를 켜고 크롬으로 접속했을 때, 통신이 맺어지자마자(`H2Bridge running`) 브라우저 쪽에서 즉시 `ERR_CONNECTION_RESET`이 뜨며 연결이 끊어지는 증상 발생.

### 🔍 원인 분석
`Http2Engine::process()` 내에서 소켓 상태를 감시하기 위해 `select(0, &rfds, &wfds, nullptr, &tv)`를 호출하고 있었다.
- **Windows (Winsock):** `select()`의 첫 번째 인자(`nfds`)는 하위 호환성을 위해 존재할 뿐 **실제로는 무시된다.** 따라서 `0`을 넣어도 전혀 문제가 되지 않는다.
- **Mac/Linux (POSIX):** `select()`의 첫 번째 인자는 **반드시 `가장 큰 파일 디스크립터 번호 + 1`** 이어야 한다. `0`을 넣으면 "아무 소켓도 감시하지 마"라는 의미가 되어버린다. 
  - 결과적으로 `select()`는 소켓을 감시하지 않고 타임아웃만 처리하거나 바로 리턴해버렸고, 루프가 종료(`r <= 0`)되면서 소켓 연결이 비정상 종료되어 브라우저에 리셋 에러가 떴다.

### 🛠 해결
`Platform.h` 환경이 아닐 경우(POSIX 환경), `std::max(clientSock, upstreamSock) + 1`을 계산하여 명시적으로 첫 번째 인자에 넣어주도록 수정.
```cpp
int nfds = 0;
#ifndef _WIN32
nfds = std::max((int)br.csock, (int)br.usock) + 1;
#endif
int r = select(nfds, &rfds, &wfds, nullptr, &tv);
```

---

## 2. `SIGPIPE` 시그널로 인한 프로세스 비정상 종료(Crash)

### ❌ 현상
1번 버그를 고치고 다시 통신을 시도했으나, 이번에는 에러 로그 하나 없이 **프록시 프로세스 자체가 조용히 죽어버리는 현상(Crash)** 발생.

### 🔍 원인 분석
서버나 클라이언트 측에서 먼저 네트워크 연결을 끊어버린 상태(Broken Pipe)에서 소켓에 데이터를 `send/write` 하려고 할 때 발생하는 OS 차이이다.
- **Windows:** 프로세스를 죽이지 않고, 단지 소켓 함수가 `SOCKET_ERROR`(-1)를 반환할 뿐이다. 에러 코드(`WSAECONNRESET`)를 보고 처리하면 된다.
- **Mac/Linux (POSIX):** 죽은 소켓에 쓰기를 시도하면 OS가 프로세스에 **`SIGPIPE` 시그널**을 날리며, 이 시그널의 기본 동작은 **"프로세스 강제 종료"**이다.

### 🛠 해결
프로그램 진입점인 `main.cpp` 최상단에서 POSIX 시스템일 경우 `SIGPIPE` 시그널을 전역적으로 무시(`SIG_IGN`)하도록 설정하여, 비정상 종료 대신 에러 코드로 안전하게 반환받도록 처리했다.
```cpp
int main() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    // ...
}
```
