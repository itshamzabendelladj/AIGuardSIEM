add_library(aiguard_storage STATIC
    src/lsm_index.cpp
    src/memtable.cpp
    src/sstable.cpp
    src/query_engine.cpp)

target_include_directories(aiguard_storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_storage PUBLIC
    aiguard_common
    fmt::fmt
    spdlog::spdlog
    ${ROCKSDB_LIBRARIES})

target_compile_options(aiguard_storage PRIVATE ${AIGUARD_SIMD_FLAGS})
