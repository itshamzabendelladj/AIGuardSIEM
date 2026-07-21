#include <gtest/gtest.h>
#include "aiguard/engine/correlation_engine.h"
#include <memory>

using namespace aiguard;

TEST(CorrelationEngineTest, AddRemoveRule) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-001";
    rule->name = "Test Rule";
    rule->threshold = 1;

    engine.add_rule(std::move(rule));
    EXPECT_EQ(engine.rule_count(), 1);

    EXPECT_TRUE(engine.remove_rule("test-001"));
    EXPECT_EQ(engine.rule_count(), 0);
}

TEST(CorrelationEngineTest, SimpleMatch) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-002";
    rule->name = "SSH Brute Force";
    rule->threshold = 3;
    rule->time_window_ms = 60000;
    rule->aggregation_field = "source.ip";
    rule->conditions.push_back({"event.action", "=", "ssh_login_failed"});

    engine.add_rule(std::move(rule));

    // Send 3 failed SSH logins from same IP
    for (int i = 0; i < 3; ++i) {
        Event event;
        event.id = Event::generate_id();
        event.timestamp = Event::now();
        event.action = "ssh_login_failed";
        event.source_ip = "10.0.0.1";
        auto alerts = engine.process_event(event);
        if (i == 2) {
            EXPECT_EQ(alerts.size(), 1);
            EXPECT_EQ(alerts[0].rule_id, "test-002");
            EXPECT_EQ(alerts[0].match_count, 3);
        } else {
            EXPECT_EQ(alerts.size(), 0);
        }
    }
}

TEST(CorrelationEngineTest, NoMatchWrongCondition) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-003";
    rule->name = "Malware Detection";
    rule->threshold = 1;
    rule->conditions.push_back({"process.name", "=", "malware.exe"});

    engine.add_rule(std::move(rule));

    Event event;
    event.id = Event::generate_id();
    event.timestamp = Event::now();
    event.process_name = "notepad.exe";
    auto alerts = engine.process_event(event);
    EXPECT_EQ(alerts.size(), 0);
}

TEST(CorrelationEngineTest, ConditionOperators) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-004";
    rule->name = "Contains Test";
    rule->threshold = 1;
    rule->conditions.push_back({"process.name", "contains", "malware"});
    engine.add_rule(std::move(rule));

    Event event;
    event.id = Event::generate_id();
    event.timestamp = Event::now();
    event.process_name = "my_malware_variant.exe";
    auto alerts = engine.process_event(event);
    EXPECT_EQ(alerts.size(), 1);
}

TEST(CorrelationEngineTest, TimeWindowExpiry) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-005";
    rule->name = "Time Window Test";
    rule->threshold = 2;
    rule->time_window_ms = 100;  // 100ms window
    rule->aggregation_field = "source.ip";
    rule->conditions.push_back({"event.action", "=", "test"});
    engine.add_rule(std::move(rule));

    // First event
    Event event1;
    event1.id = Event::generate_id();
    event1.timestamp = Event::now();
    event1.action = "test";
    event1.source_ip = "1.2.3.4";
    engine.process_event(event1);

    // Wait for window to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Second event after window expired
    Event event2;
    event2.id = Event::generate_id();
    event2.timestamp = Event::now();
    event2.action = "test";
    event2.source_ip = "1.2.3.4";
    auto alerts = engine.process_event(event2);
    EXPECT_EQ(alerts.size(), 0);  // No alert because first event expired
}

TEST(CorrelationEngineTest, Stats) {
    CorrelationEngine engine;
    auto rule = std::make_unique<CorrelationRule>();
    rule->id = "test-006";
    rule->name = "Stats Test";
    rule->threshold = 1;
    rule->conditions.push_back({"event.action", "=", "trigger"});
    engine.add_rule(std::move(rule));

    Event event;
    event.id = Event::generate_id();
    event.timestamp = Event::now();
    event.action = "trigger";
    engine.process_event(event);

    auto stats = engine.get_stats();
    EXPECT_EQ(stats.events_processed, 1);
    EXPECT_EQ(stats.alerts_generated, 1);
}
