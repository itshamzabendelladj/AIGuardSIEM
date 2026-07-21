add_executable(aiguard_winlog_collector
    src/winlog_collector.cpp
    src/winlog_parser.cpp
    src/winlog_server.cpp)

target_include_directories(aiguard_winlog_collector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_winlog_collector PRIVATE
    aiguard_common
    fmt::fmt
    spdlog::spdlog)
