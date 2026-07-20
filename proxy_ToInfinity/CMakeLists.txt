cmake_minimum_required(VERSION 3.15)
project(proxy_ToInfinity CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add source files
set(SOURCES
    src/main.cpp
    src/Core/Logger.cpp
    src/Core/ProxyServer.cpp
    src/Crypto/TlsManager.cpp
    src/Protocol/Http1Engine.cpp
    src/Protocol/Http2Engine.cpp
    src/Inspector/TrafficAnalyzer.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Find and link OpenSSL (assuming vcpkg integration)
# When building, user should run: 
# cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
find_package(OpenSSL REQUIRED)

# zlib(gzip/deflate)·brotli(br) — Content-Encoding 해제용. 둘 다 CMake config 제공.
find_package(ZLIB REQUIRED)
find_package(unofficial-brotli CONFIG REQUIRED)

# vcpkg의 nghttp2 포트는 CMake config(find_package)를 제공하지 않으므로
# import 라이브러리(nghttp2.lib)를 직접 찾아 링크한다.
find_library(NGHTTP2_LIBRARY NAMES nghttp2 REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${NGHTTP2_LIBRARY}
    ZLIB::ZLIB
    unofficial::brotli::brotlidec
    unofficial::brotli::brotlicommon
)

# Windows 소켓/인증서 라이브러리
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 crypt32)
endif()

# 한글 UTF-8 주석 경고(C4819) 방지
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
