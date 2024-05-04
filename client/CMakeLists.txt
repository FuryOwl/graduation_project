cmake_minimum_required(VERSION 3.11)
project(client)
set(CMAKE_CXX_STANDARD 14)

add_executable(client client.cpp getopt_win32.h getopt_win32.c)
target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_SSL_PATH "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD")
    set(OPENSSL_CRYPTO_PATH "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD")

    include_directories(${OPENSSL_INCLUDE_DIR})

    find_library(OPENSSL_SSL NAMES ssl libssl ssleay32 PATHS ${OPENSSL_SSL_PATH} NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO NAMES crypto libcrypto libeay32 PATHS ${OPENSSL_CRYPTO_PATH} NO_DEFAULT_PATH)

    if(OPENSSL_SSL AND OPENSSL_CRYPTO)
        message(STATUS "Found OpenSSL SSL: ${OPENSSL_SSL}")
        message(STATUS "Found OpenSSL Crypto: ${OPENSSL_CRYPTO}")
        target_link_libraries(client PRIVATE ${OPENSSL_SSL} ${OPENSSL_CRYPTO})
    else()
        message(FATAL_ERROR "Could not find OpenSSL libraries on Windows")
    endif()

    target_compile_definitions(client PRIVATE WIN32)
    target_link_libraries(client PRIVATE ws2_32)  # Link the Winsock library

elseif(UNIX)
    find_package(OpenSSL REQUIRED)
    if(OPENSSL_FOUND)
        message(STATUS "Found OpenSSL version ${OPENSSL_VERSION}")
        message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
        target_include_directories(client PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(client PRIVATE ${OPENSSL_LIBRARIES} pthread)
    endif()

    target_compile_definitions(client PRIVATE UNIX)
endif()


