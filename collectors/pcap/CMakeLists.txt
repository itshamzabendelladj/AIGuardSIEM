add_executable(aiguard_pcap_collector
    src/dpdk_capture.cpp
    src/pcap_capture.cpp
    src/flow_tracker.cpp
    src/pcap_server.cpp)

target_include_directories(aiguard_pcap_collector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_pcap_collector PRIVATE
    aiguard_common
    fmt::fmt
    spdlog::spdlog
    ${RDKAFKA_LIBRARIES})

if(AIGUARD_ENABLE_DPDK)
    target_compile_definitions(aiguard_pcap_collector PRIVATE AIGUARD_DPDK_ENABLED)
    target_link_libraries(aiguard_pcap_collector PRIVATE -lrte_eal -lrte_mbuf -lrte_mempool)
endif()

target_compile_options(aiguard_pcap_collector PRIVATE ${AIGUARD_SIMD_FLAGS})
