# AIGuardSIEM - Production SIEM/XDR Platform
# Copyright (c) 2024 AIGuard. All rights reserved.
cmake_minimum_required(VERSION 3.22)

project(AIGuardSIEM
    VERSION 1.0.0
    DESCRIPTION "Production SIEM/XDR Platform"
    LANGUAGES CXX Go)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Position-independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(AIGUARD_BUILD_TESTS "Build unit tests" ON)
option(AIGUARD_BUILD_BENCHMARKS "Build benchmarks" ON)
option(AIGUARD_ENABLE_DPDK "Enable DPDK support" OFF)
option(AIGUARD_ENABLE_AVX512 "Enable AVX-512 instructions" ON)
option(AIGUARD_ENABLE_CUDA "Enable CUDA for GPU inference" OFF)
option(AIGUARD_ENABLE_LTO "Enable link-time optimization" OFF)

if(AIGUARD_ENABLE_LTO)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# FetchContent for dependencies
include(FetchContent)

# fmt
FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.1.1)
FetchContent_MakeAvailable(fmt)

# spdlog
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0)
FetchContent_MakeAvailable(spdlog)

# Boost (header-only components)
find_package(Boost 1.82 REQUIRED COMPONENTS
    system thread lockfree graph program_options regex)

# OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# librdkafka
find_package(PkgConfig REQUIRED)
pkg_check_modules(RDKAFKA REQUIRED rdkafka)

# ONNX Runtime
find_package(onnxruntime CONFIG QUIET)
if(NOT onnxruntime_FOUND)
    set(ONNXRUNTIME_ROOT_DIR "" CACHE PATH "Path to ONNX Runtime installation")
    if(ONNXRUNTIME_ROOT_DIR)
        set(ONNXRUNTIME_INCLUDE_DIRS ${ONNXRUNTIME_ROOT_DIR}/include)
        set(ONNXRUNTIME_LIBRARIES ${ONNXRUNTIME_ROOT_DIR}/lib/libonnxruntime.so)
    endif()
endif()

# RocksDB
pkg_check_modules(ROCKSDB REQUIRED rocksdb)

# GoogleTest
if(AIGUARD_BUILD_TESTS)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

# Common include directory
include_directories(${CMAKE_SOURCE_DIR}/collectors/common/include)

# AVX-512 flag
if(AIGUARD_ENABLE_AVX512)
    set(AIGUARD_SIMD_FLAGS "-mavx512f -mavx512bw -mavx512dq")
    add_compile_definitions(AIGUARD_AVX512)
endif()

# Subdirectories
add_subdirectory(collectors)
add_subdirectory(engine)
add_subdirectory(storage)
add_subdirectory(xdr)
add_subdirectory(crypto)

if(AIGUARD_BUILD_TESTS)
    add_subdirectory(collectors/syslog/tests)
    add_subdirectory(collectors/pcap/tests)
    add_subdirectory(collectors/netflow/tests)
    add_subdirectory(engine/correlation/tests)
    add_subdirectory(engine/rules/tests)
    add_subdirectory(storage/hot/tests)
    add_subdirectory(crypto/tests)
endif()

# Install rules
include(GNUInstallDirs)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/collectors/common/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aiguard)
