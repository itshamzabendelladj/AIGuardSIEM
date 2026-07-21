add_library(aiguard_engine STATIC
    src/stream_processor.cpp
    src/correlation_engine.cpp
    src/event_window.cpp)

target_include_directories(aiguard_engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_engine PUBLIC
    aiguard_common
    fmt::fmt
    spdlog::spdlog
    ${RDKAFKA_LIBRARIES}
    Boost::lockfree)

target_compile_options(aiguard_engine PRIVATE ${AIGUARD_SIMD_FLAGS})
