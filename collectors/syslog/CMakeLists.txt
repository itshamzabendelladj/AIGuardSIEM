add_executable(aiguard_syslog_collector
    src/syslog_collector.cpp
    src/syslog_parser.cpp
    src/syslog_server.cpp)

target_include_directories(aiguard_syslog_collector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_syslog_collector PRIVATE
    aiguard_common
    fmt::fmt
    spdlog::spdlog
    OpenSSL::SSL
    OpenSSL::Crypto)

target_compile_options(aiguard_syslog_collector PRIVATE
    ${AIGUARD_SIMD_FLAGS})
