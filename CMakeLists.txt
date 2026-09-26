cmake_minimum_required(VERSION 3.15)

set(CMAKE_TOOLCHAIN_FILE "D:/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "" FORCE)

project(hackatonServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/FS)
endif()

include(FetchContent)

if(WIN32)
    FetchContent_Declare(
        openssl
        GIT_REPOSITORY https://github.com/janbar/openssl-cmake.git
        GIT_TAG        master
    )
    FetchContent_MakeAvailable(openssl)

    if(NOT TARGET OpenSSL::Crypto)
        add_library(OpenSSL::Crypto ALIAS crypto)
    endif()
    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL ALIAS ssl)
    endif()
else()
    find_package(OpenSSL REQUIRED)
endif()

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(asio)

FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        master
)

FetchContent_Populate(jwt-cpp)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG master
)
FetchContent_MakeAvailable(json)


find_package(libpqxx CONFIG REQUIRED)

find_path(ASIO_INC_DIR asio.hpp HINTS "${asio_SOURCE_DIR}/asio/include" "${asio_SOURCE_DIR}/include" "${asio_SOURCE_DIR}")

find_package(Threads REQUIRED)

add_executable(hackatonServer 
    src/main.cpp 
    src/database.cpp    
    include/common.h 
    include/server.h 
    include/session.h
    include/database.h
)

target_compile_definitions(hackatonServer PRIVATE ASIO_STANDALONE ASIO_HAS_OPENSSL)

target_include_directories(hackatonServer PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include 
    ${ASIO_INC_DIR}
    ${jwt-cpp_SOURCE_DIR}/include
)
target_link_libraries(hackatonServer PRIVATE 
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    nlohmann_json::nlohmann_json
    libpqxx::pqxx
    libsodium::sodium
)

if (MSVC)
    target_compile_options(hackatonServer PRIVATE /Zc:preprocessor /Zc:__cplusplus)
endif()