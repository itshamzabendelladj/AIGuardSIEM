add_executable(crypto_tests
    test_crypto.cpp)

target_link_libraries(crypto_tests PRIVATE
    aiguard_crypto
    GTest::gtest_main)

target_include_directories(crypto_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto/include)

gtest_discover_tests(crypto_tests)
