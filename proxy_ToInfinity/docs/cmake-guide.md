# CMake 가이드 — 이 프로젝트는 왜/어떻게 CMake로 빌드하나

> proxy_ToInfinity를 **cl.exe 직접 컴파일 → CMake**로 옮긴 과정과 개념 정리.
> (cl.exe 단발 빌드는 검증용이었고, 정식 빌드 방식은 CMake다.)

## 1. CMake가 뭔가 (개념)

**CMake는 컴파일러가 아니다. "빌드 시스템 생성기(build-system generator)"다.**
- 너는 `CMakeLists.txt`에 **"무엇을 빌드하는지"**(소스 목록, 의존 라이브러리, 옵션)를 선언한다.
- `cmake`를 돌리면, 그 선언을 읽어 **네 플랫폼/툴체인에 맞는 실제 빌드 파일**(Windows면 Visual Studio 솔루션 `.sln`/`.vcxproj`, 리눅스면 Makefile/Ninja)을 **생성**한다. (= configure/generate 단계)
- 그다음 실제 컴파일은 그 생성된 빌드 도구(MSBuild, ninja 등)가 한다. (= build 단계)

즉 **2단계**다: ① `cmake`로 빌드파일 생성 → ② `cmake --build`로 컴파일.

## 2. 왜 cl.exe 대신 CMake인가

| | cl.exe 직접 | CMake |
|---|---|---|
| 대상 | 파일 1~2개 수동 | **여러 파일 + 여러 의존성** 자동 관리 |
| 의존 라이브러리 | 경로·lib 이름을 손으로 다 나열 | `find_package`/`find_library`가 찾아줌 |
| Debug/Release·x64 | 매번 플래그 수동 | `--config`로 전환 |
| 크로스플랫폼 | Windows 전용 명령 | 같은 CMakeLists로 리눅스/맥도 |
| DLL 배치 | 수동 복사 | vcpkg 연동 시 **자동 배치** |

proxy_ToInfinity는 소스 7개 + 외부 의존 4개(OpenSSL, nghttp2, zlib, brotli)라 CMake가 맞다. (cl.exe는 "컴파일 에러 빨리 잡기"용 임시로만 썼다.)

## 3. cl.exe → CMake 전환에서 실제로 겪은 것 (추적 기록)

1. **cmake 확보:** PATH엔 없지만 VS2022에 번들됨
   (`...\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`).
2. **configure (vcpkg 툴체인 필수):**
   ```
   cmake -B build -S . -G "Visual Studio 17 2022" -A x64 \
         -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   ```
   → `-DCMAKE_TOOLCHAIN_FILE=...vcpkg.cmake`가 있어야 `find_package(OpenSSL)` 등이 vcpkg 설치본을 찾는다. (이게 없으면 의존성을 못 찾음)
3. **1차 빌드 실패:** `LNK1181: nghttp2.lib 열 수 없음`.
   원인: **vcpkg의 nghttp2 포트는 CMake config를 제공하지 않는다**(share에 copyright/spdx뿐). 그래서 CMakeLists에 맨이름 `nghttp2`로 링크하면 라이브러리 경로를 못 찾는다.
   해결: `find_library(NGHTTP2_LIBRARY NAMES nghttp2 REQUIRED)`로 lib 절대경로를 찾아 링크.
4. **zlib/brotli 추가(Content-Encoding용):** 이건 CMake config를 제공 → `find_package(ZLIB REQUIRED)`(빌트인) + `find_package(unofficial-brotli CONFIG REQUIRED)`.
5. **한글 주석 경고(C4819):** MSVC에 소스가 UTF-8임을 알려야 함 → `target_compile_options(... /utf-8)`.
6. **결과:** 빌드 성공 + vcpkg가 필요한 DLL(libssl/libcrypto/nghttp2/brotli\*)을 `build/Release/`에 **자동 배치**.

## 4. 빌드 방법 (현재 정식)

```
cd proxy_ToInfinity
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
# 산출물: build/Release/proxy_ToInfinity.exe  (의존 DLL 자동 배치됨)
# 실행 전: rootCA.crt / rootCA.key 를 build/Release/ 에 복사 (프록시가 CWD에서 로드)
```
사전조건: vcpkg에 `openssl nghttp2 zlib brotli` (x64-windows) 설치.

## 5. CMakeLists.txt 한눈에 (무슨 줄이 무슨 뜻)

```cmake
cmake_minimum_required(VERSION 3.15)     # 최소 CMake 버전
project(proxy_ToInfinity CXX)            # 프로젝트 이름 + C++
set(CMAKE_CXX_STANDARD 17)               # C++17 (filesystem/std 등)

set(SOURCES src/main.cpp ...)            # 컴파일할 소스 목록
add_executable(${PROJECT_NAME} ${SOURCES})   # 이 소스들로 exe 생성
target_include_directories(... src)      # #include "Core/Logger.h" 를 src 기준으로 찾게

find_package(OpenSSL REQUIRED)           # OpenSSL 찾기 → OpenSSL::SSL/Crypto 타깃
find_package(ZLIB REQUIRED)              # zlib → ZLIB::ZLIB
find_package(unofficial-brotli CONFIG REQUIRED)   # brotli → unofficial::brotli::*
find_library(NGHTTP2_LIBRARY NAMES nghttp2 REQUIRED)  # nghttp2는 config 없어 lib 직접 탐색

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL OpenSSL::Crypto         # ← "임포트 타깃"(Foo::Bar): 경로·헤더·의존까지 딸려옴
    ${NGHTTP2_LIBRARY}                   # ← find_library가 찾은 절대경로
    ZLIB::ZLIB
    unofficial::brotli::brotlidec unofficial::brotli::brotlicommon)

if(WIN32) target_link_libraries(... ws2_32 crypt32) endif()   # Windows 소켓/인증서
if(MSVC)  target_compile_options(... /utf-8) endif()          # 한글 주석 경고 방지
```

## 6. 알아둘 개념 (용어)

- **configure vs build:** cmake는 먼저 "빌드파일 생성"(configure/generate), 그다음 "실제 컴파일"(build). 두 단계.
- **generator (`-G`):** 어떤 빌드 시스템을 생성할지. 여기선 "Visual Studio 17 2022".
- **toolchain file (`-DCMAKE_TOOLCHAIN_FILE`):** 툴체인/의존성 검색 경로 주입. vcpkg 연동의 핵심.
- **out-of-source build (`-B build`):** 소스와 분리된 `build/` 폴더에 빌드 산출물을 몰아넣음(소스 오염 방지). → `build/`는 gitignore.
- **`find_package` vs `find_library`:** 전자는 라이브러리가 제공하는 **CMake config**(임포트 타깃 `Foo::Bar` 포함)를 찾음(권장). 후자는 그냥 `.lib` 파일 하나를 경로로 찾음(config 없는 nghttp2용 대안).
- **임포트 타깃(`OpenSSL::SSL` 등):** 라이브러리의 경로+헤더+하위 의존을 한 덩어리로 들고 있는 타깃. 링크만 걸면 include 경로까지 자동.

## 관련
- 빌드/검증 현황: `build-and-progress.md`
- 계획↔코드 차이 추적: `phase5-vs-code-tracking.md`
