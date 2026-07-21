#include <gtest/gtest.h>
#include "aiguard/engine/sigma_compiler.h"
#include <string>

using namespace aiguard;

TEST(SigmaCompilerTest, CompileSimpleRule) {
    std::string yaml = R"(
title: Test Detection Rule
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Test rule for unit testing
author: Test
level: high
tags:
  - attack.initial_access
  - attack.t1190
detection:
  selection:
    event.action: ssh_login_failed
  condition: selection
)";

    SigmaCompiler compiler;
    auto rule = compiler.compile(yaml);
    ASSERT_NE(rule, nullptr);
    EXPECT_EQ(rule->id, "12345678-1234-1234-1234-123456789012");
    EXPECT_EQ(rule->name, "Test Detection Rule");
    EXPECT_EQ(rule->severity, Severity::High);
}

TEST(SigmaCompilerTest, MapLevel) {
    SigmaCompiler compiler;
    // Test via compiled rule
    std::string yaml = R"(
title: Critical Rule
id: 11111111-1111-1111-1111-111111111111
level: critical
detection:
  selection:
    process.name: test.exe
  condition: selection
)";
    auto rule = compiler.compile(yaml);
    ASSERT_NE(rule, nullptr);
    EXPECT_EQ(rule->severity, Severity::Critical);
}

TEST(SigmaCompilerTest, StatsTracking) {
    SigmaCompiler compiler;
    std::string yaml = R"(
title: Stats Test
id: 22222222-2222-2222-2222-222222222222
level: medium
detection:
  selection:
    event.action: test
  condition: selection
)";
    compiler.compile(yaml);
    auto stats = compiler.get_stats();
    EXPECT_EQ(stats.rules_compiled, 1);
}
