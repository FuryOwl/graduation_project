cmake_minimum_required(VERSION 3.11)
project(server)

set(CMAKE_CXX_STANDARD 14)

# Пути к OpenSSL
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(server server.cpp sqlite3.h sqlite3.c)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Явное добавление библиотек
find_library(OPENSSL_SSL NAMES ssl libssl ssleay32 PATHS "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" NO_DEFAULT_PATH)
find_library(OPENSSL_CRYPTO NAMES crypto libcrypto libeay32 PATHS "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" NO_DEFAULT_PATH)

if(OPENSSL_SSL AND OPENSSL_CRYPTO)
    message(STATUS "Found OpenSSL SSL: ${OPENSSL_SSL}")
    message(STATUS "Found OpenSSL Crypto: ${OPENSSL_CRYPTO}")
    target_link_libraries(server PRIVATE ${OPENSSL_SSL} ${OPENSSL_CRYPTO})
else()
    message(FATAL_ERROR "Could not find OpenSSL libraries")
endif()

if(UNIX)
    target_compile_definitions(server PRIVATE UNIX)
    target_link_libraries( PRIVATE pthread)  # Link the pthread library
elseif(WIN32)
    target_compile_definitions(server PRIVATE WIN32)
    target_link_libraries(server PRIVATE ws2_32)  # Link the Winsock library
endif()

