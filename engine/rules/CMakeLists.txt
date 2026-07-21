add_library(aiguard_rules STATIC
    src/sigma_compiler.cpp
    src/rule_engine.cpp)

target_include_directories(aiguard_rules PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(aiguard_rules PUBLIC
    aiguard_common
    aiguard_engine
    fmt::fmt
    spdlog::spdlog)
