add_executable(aiguard_netflow_collector
    src/netflow_collector.cpp
    src/netflow_parser.cpp
    src/netflow_server.cpp)

target_include_directories(aiguard_netflow_collector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_netflow_collector PRIVATE
    aiguard_common
    fmt::fmt
    spdlog::spdlog)
