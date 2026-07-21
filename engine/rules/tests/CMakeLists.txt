add_executable(rules_tests
    test_sigma_compiler.cpp)

target_link_libraries(rules_tests PRIVATE
    aiguard_rules
    aiguard_engine
    aiguard_common
    GTest::gtest_main)

target_include_directories(rules_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/engine/rules/include)

gtest_discover_tests(rules_tests)
