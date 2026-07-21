add_executable(engine_tests
    test_correlation_engine.cpp
    test_event_windows.cpp)

target_link_libraries(engine_tests PRIVATE
    aiguard_engine
    aiguard_common
    GTest::gtest_main)

target_include_directories(engine_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/engine/correlation/include)

gtest_discover_tests(engine_tests)
