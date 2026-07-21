add_executable(syslog_tests
    test_syslog_parser.cpp
    test_syslog_collector.cpp)

target_link_libraries(syslog_tests PRIVATE
    aiguard_syslog_collector
    aiguard_common
    GTest::gtest_main)

target_include_directories(syslog_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/collectors/syslog/include)

gtest_discover_tests(syslog_tests)
