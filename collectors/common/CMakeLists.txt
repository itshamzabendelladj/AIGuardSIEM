add_library(aiguard_common STATIC
    src/event.cpp
    src/ecs_schema.cpp
    src/kafka_producer.cpp
    src/kafka_consumer.cpp
    src/circular_buffer.cpp
    src/thread_pool.cpp
    src/metrics.cpp
    src/config.cpp)

target_include_directories(aiguard_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS})

target_link_libraries(aiguard_common PUBLIC
    fmt::fmt
    spdlog::spdlog
    ${RDKAFKA_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto)

target_compile_features(aiguard_common PUBLIC cxx_std_20)
