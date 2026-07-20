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
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Link Windows Socket Library
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 crypt32)
endif()
