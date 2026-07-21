#include <gtest/gtest.h>
#include "aiguard/syslog/syslog_collector.h"
#include "aiguard/syslog/syslog_parser.h"
#include "aiguard/common/event.h"
#include "aiguard/common/ecs_schema.h"
#include <string>

using namespace aiguard;

TEST(SyslogCollectorTest, ConfigDefaults) {
    SyslogCollectorConfig config;
    EXPECT_EQ(config.udp_port, 514);
    EXPECT_EQ(config.tcp_port, 514);
    EXPECT_EQ(config.tls_port, 6514);
    EXPECT_EQ(config.bind_address, "0.0.0.0");
    EXPECT_EQ(config.worker_threads, 4);
    EXPECT_EQ(config.batch_size, 1000);
    EXPECT_EQ(config.ring_buffer_capacity, 1048576);
}

TEST(SyslogCollectorTest, ECSNormalization) {
    ECSNormalizer normalizer;
    auto event = std::make_unique<Event>();
    event->source_type = "syslog";
    event->set_field("host", "myhost");
    event->set_field("program", "myapp");
    event->set_field("severity", "error");
    event->set_field("facility", "auth");

    normalizer.normalize(*event, "syslog");

    EXPECT_EQ(event->host_name, "myhost");
    EXPECT_EQ(event->process_name, "myapp");
    EXPECT_EQ(event->severity, "error");
}

TEST(SyslogCollectorTest, EventToJsonRoundTrip) {
    auto event = std::make_unique<Event>();
    event->id = 12345;
    event->timestamp = Event::now();
    event->source_ip = "192.168.1.100";
    event->source_port = 12345;
    event->destination_ip = "10.0.0.1";
    event->destination_port = 80;
    event->host_name = "test-host";
    event->category = "network";
    event->type = "connection";
    event->action = "connect";
    event->severity = "high";
    event->severity_score = 75;
    event->set_field("custom_field", std::string("custom_value"));
    event->set_field("numeric_field", static_cast<int64_t>(42));

    std::string json = event->to_json();
    EXPECT_FALSE(json.empty());

    auto restored = Event::from_json(json);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->id, 12345);
    EXPECT_EQ(restored->source_ip, "192.168.1.100");
    EXPECT_EQ(restored->source_port, 12345);
    EXPECT_EQ(restored->destination_ip, "10.0.0.1");
    EXPECT_EQ(restored->destination_port, 80);
    EXPECT_EQ(restored->host_name, "test-host");
    EXPECT_EQ(restored->category, "network");
    EXPECT_EQ(restored->severity, "high");
    EXPECT_EQ(restored->severity_score, 75);
}

TEST(SyslogCollectorTest, EventFromInvalidJson) {
    auto result = Event::from_json("not valid json");
    EXPECT_EQ(result, nullptr);
}

TEST(SyslogCollectorTest, CircularBufferBasic) {
    LockFreeCircularBuffer<int, 1024> buffer;

    EXPECT_TRUE(buffer.empty());
    EXPECT_FALSE(buffer.full());

    ASSERT_TRUE(buffer.try_push(42));
    EXPECT_FALSE(buffer.empty());

    auto val = buffer.try_pop();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 42);
    EXPECT_TRUE(buffer.empty());
}

TEST(SyslogCollectorTest, CircularBufferFullEmpty) {
    LockFreeCircularBuffer<int, 4> buffer;

    EXPECT_TRUE(buffer.try_push(1));
    EXPECT_TRUE(buffer.try_push(2));
    EXPECT_TRUE(buffer.try_push(3));
    EXPECT_FALSE(buffer.try_push(4));  // Full (capacity-1 usable)

    auto val = buffer.try_pop();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, 1);

    ASSERT_TRUE(buffer.try_push(4));

    val = buffer.try_pop();
    EXPECT_EQ(*val, 2);
    val = buffer.try_pop();
    EXPECT_EQ(*val, 3);
    val = buffer.try_pop();
    EXPECT_EQ(*val, 4);
    EXPECT_FALSE(buffer.try_pop().has_value());
}

TEST(SyslogCollectorTest, ConcurrentRingBufferBasic) {
    ConcurrentRingBuffer<std::string> buffer(1024);

    EXPECT_TRUE(buffer.try_push(std::string("hello")));
    auto val = buffer.try_pop();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, "hello");
}

TEST(SyslogCollectorTest, MetricsCounter) {
    Counter counter("test_counter");
    EXPECT_EQ(counter.get(), 0);
    counter.increment();
    counter.increment(5);
    EXPECT_EQ(counter.get(), 6);
    counter.reset();
    EXPECT_EQ(counter.get(), 0);
}

TEST(SyslogCollectorTest, MetricsGauge) {
    Gauge gauge("test_gauge");
    gauge.set(42.0);
    EXPECT_DOUBLE_EQ(gauge.get(), 42.0);
    gauge.increment(8.0);
    EXPECT_DOUBLE_EQ(gauge.get(), 50.0);
    gauge.decrement(10.0);
    EXPECT_DOUBLE_EQ(gauge.get(), 40.0);
}

TEST(SyslogCollectorTest, MetricsHistogram) {
    Histogram hist("test_hist", {1.0, 5.0, 10.0, 50.0, 100.0});
    hist.observe(2.0);
    hist.observe(7.0);
    hist.observe(20.0);
    hist.observe(80.0);

    auto snap = hist.snapshot();
    EXPECT_EQ(snap.count, 4);
    EXPECT_DOUBLE_EQ(snap.sum, 109.0);
}
