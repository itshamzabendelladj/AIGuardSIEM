add_library(aiguard_xdr_agent STATIC
    common/src/agent_core.cpp
    common/src/event_collector.cpp
    common/src/agent_comms.cpp)

target_include_directories(aiguard_xdr_agent PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include)

target_link_libraries(aiguard_xdr_agent PUBLIC
    aiguard_common
    fmt::fmt
    spdlog::spdlog
    OpenSSL::SSL
    OpenSSL::Crypto)

# Linux-specific agent
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(aiguard_xdr_agent_linux
        linux/kprobe_monitor.cpp
        linux/ebpf_tracer.cpp
        linux/agent_main.cpp)

    target_link_libraries(aiguard_xdr_agent_linux PRIVATE
        aiguard_xdr_agent_agent)

    target_compile_options(aiguard_xdr_agent_linux PRIVATE ${AIGUARD_SIMD_FLAGS})
endif()
