#include <gtest/gtest.h>
#include "aiguard/engine/event_windows.h"
#include <chrono>

using namespace aiguard;

TEST(EventWindowTest, TumblingWindowBasic) {
    EventWindowManager manager;

    WindowSpec spec;
    spec.id = "test-tumbling";
    spec.type = WindowType::Tumbling;
    spec.window_size_ms = 1000;
    spec.aggregation_function = "count";
    spec.threshold = 5.0;

    manager.add_window(spec);

    // Add 3 events
    for (int i = 0; i < 3; ++i) {
        Event event;
        event.id = Event::generate_id();
        event.timestamp = Event::now();
        event.source_ip = "10.0.0.1";
        manager.process_event(event);
    }

    EXPECT_GT(manager.active_window_count(), 0);
}

TEST(EventWindowTest, SessionWindowTimeout) {
    EventWindowManager manager;

    WindowSpec spec;
    spec.id = "test-session";
    spec.type = WindowType::Session;
    spec.gap_timeout_ms = 50;
    spec.aggregation_function = "count";
    spec.threshold = 100.0;

    manager.add_window(spec);

    Event event1;
    event1.id = Event::generate_id();
    event1.timestamp = Event::now();
    event1.source_ip = "10.0.0.1";
    manager.process_event(event1);

    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    Event event2;
    event2.id = Event::generate_id();
    event2.timestamp = Event::now();
    event2.source_ip = "10.0.0.1";
    manager.process_event(event2);
}

TEST(EventWindowTest, HoppingWindow) {
    EventWindowManager manager;

    WindowSpec spec;
    spec.id = "test-hopping";
    spec.type = WindowType::Hopping;
    spec.window_size_ms = 5000;
    spec.slide_size_ms = 1000;
    spec.aggregation_function = "count";

    manager.add_window(spec);

    Event event;
    event.id = Event::generate_id();
    event.timestamp = Event::now();
    event.source_ip = "10.0.0.1";
    manager.process_event(event);

    EXPECT_GT(manager.active_window_count(), 0);
}

TEST(EventWindowTest, GroupByField) {
    EventWindowManager manager;

    WindowSpec spec;
    spec.id = "test-groupby";
    spec.type = WindowType::Tumbling;
    spec.window_size_ms = 60000;
    spec.group_by_field = "source.ip";
    spec.aggregation_function = "count";

    manager.add_window(spec);

    for (int i = 0; i < 5; ++i) {
        Event event;
        event.id = Event::generate_id();
        event.timestamp = Event::now();
        event.source_ip = "192.168.1." + std::to_string(100 + i);
        manager.process_event(event);
    }

    EXPECT_GT(manager.active_window_count(), 0);
}

TEST(EventWindowTest, ExpireWindows) {
    EventWindowManager manager;

    WindowSpec spec;
    spec.id = "test-expire";
    spec.type = WindowType::Tumbling;
    spec.window_size_ms = 50;  // Very short window
    spec.aggregation_function = "count";

    manager.add_window(spec);

    Event event;
    event.id = Event::generate_id();
    event.timestamp = Event::now() - std::chrono::seconds(1);
    event.source_ip = "10.0.0.1";
    manager.process_event(event);

    // Wait for window to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    auto results = manager.expire_windows();
    EXPECT_FALSE(results.empty());
}
