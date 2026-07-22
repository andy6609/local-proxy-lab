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

# zlib(gzip/deflate)·brotli(br) — Content-Encoding 해제용
find_package(ZLIB REQUIRED)

if(WIN32)
    # vcpkg 환경 (Windows)
    find_package(unofficial-brotli CONFIG REQUIRED)
    find_library(NGHTTP2_LIBRARY NAMES nghttp2 REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ${NGHTTP2_LIBRARY}
        ZLIB::ZLIB
        unofficial::brotli::brotlidec
        unofficial::brotli::brotlicommon
        ws2_32 crypt32
    )
else()
    # Homebrew 환경 (Mac/Linux)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(BROTLI REQUIRED libbrotlidec libbrotlicommon)
    pkg_check_modules(NGHTTP2 REQUIRED libnghttp2)
    
    target_include_directories(${PROJECT_NAME} PRIVATE ${NGHTTP2_INCLUDE_DIRS} ${BROTLI_INCLUDE_DIRS})
    target_link_directories(${PROJECT_NAME} PRIVATE ${NGHTTP2_LIBRARY_DIRS} ${BROTLI_LIBRARY_DIRS})
    
    target_link_libraries(${PROJECT_NAME} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ${NGHTTP2_LIBRARIES}
        ZLIB::ZLIB
        ${BROTLI_LIBRARIES}
    )
endif()

# 한글 UTF-8 주석 경고(C4819) 방지
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
