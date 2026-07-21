add_executable(storage_tests
    test_lsm_index.cpp
    test_memtable.cpp)

target_link_libraries(storage_tests PRIVATE
    aiguard_storage
    aiguard_common
    GTest::gtest_main)

target_include_directories(storage_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/storage/hot/include)

gtest_discover_tests(storage_tests)
