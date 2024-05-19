cmake_minimum_required(VERSION 3.11)
project(server)

set(CMAKE_CXX_STANDARD 14)

add_executable(server server.cpp sqlite3.h sqlite3.c)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Find Python libraries
find_package(PythonLibs REQUIRED)

# Include directories for Python
target_include_directories(server PRIVATE ${PYTHON_INCLUDE_DIRS})

# Link Python libraries
target_link_libraries(server PRIVATE ${PYTHON_LIBRARIES})

# Configuration for OpenSSL and additional system libraries
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
        target_link_libraries(server PRIVATE ${OPENSSL_SSL} ${OPENSSL_CRYPTO})
    else()
        message(FATAL_ERROR "Could not find OpenSSL libraries on Windows")
    endif()

    target_compile_definitions(server PRIVATE WIN32)
    target_link_libraries(server PRIVATE ws2_32)  # Link the Winsock library

elseif(UNIX)
    find_package(OpenSSL REQUIRED)
    if(OPENSSL_FOUND)
        message(STATUS "Found OpenSSL version ${OPENSSL_VERSION}")
        message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
        target_include_directories(server PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(server PRIVATE ${OPENSSL_LIBRARIES} pthread)
    else()
        message(FATAL_ERROR "Could not find OpenSSL libraries on UNIX")
    endif()

    target_compile_definitions(server PRIVATE UNIX)
endif()

