add_library(aiguard_crypto STATIC
    src/tls_accelerator.cpp
    src/crypto_utils.cpp)

target_include_directories(aiguard_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_crypto PUBLIC
    fmt::fmt
    spdlog::spdlog
    OpenSSL::SSL
    OpenSSL::Crypto)

target_compile_options(aiguard_crypto PRIVATE ${AIGUARD_SIMD_FLAGS})
