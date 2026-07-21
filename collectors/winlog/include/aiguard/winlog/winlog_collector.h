#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/ecs_schema.h"
#include "aiguard/common/metrics.h"
#include "aiguard/common/circular_buffer.h"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>

namespace aiguard {

/// Windows Event Log record
struct WinLogRecord {
    uint32_t event_id{0};
    std::string channel;          // Application, Security, System, etc.
    std::string provider_name;
    std::string provider_guid;
    std::string computer_name;
    std::string user_sid;
    std::string user_name;
    std::string domain;
    std::string message;
    std::string level;            // Information, Warning, Error, Critical
    uint16_t level_value{0};
    std::string task_name;
    std::string opcode_name;
    uint64_t record_id{0};
    uint64_t process_id{0};
    uint64_t thread_id{0};
    std::chrono::system_clock::time_point time_created;
    std::string raw_xml;
    std::map<std::string, std::string> event_data;
};

/// WinLog collector configuration
struct WinLogCollectorConfig {
    std::vector<std::string> channels{"Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational"};
    size_t batch_size{500};
    int batch_timeout_ms{100};
    int poll_interval_ms{1000};
    std::string kafka_brokers{"localhost:9092"};
    std::string kafka_topic{"aiguard-winlog"};
    bool enable_metrics{true};
    bool use_event_subscriptions{true};
    size_t ring_buffer_capacity{262144};
};

/// Windows Event Log collector
///
/// Uses Event Tracing for Windows (ETW) or EventLog API for real-time
/// event log streaming. On non-Windows platforms, can receive forwarded
/// events via syslog or WEC (Windows Event Collection).
class WinLogCollector {
public:
    explicit WinLogCollector(const WinLogCollectorConfig& config);
    ~WinLogCollector();

    WinLogCollector(const WinLogCollector&) = delete;
    WinLogCollector& operator=(const WinLogCollector&) = delete;

    bool start();
    void stop();
    [[nodiscard]] bool is_running() const { return running_.load(); }

    /// Ingest a raw XML event (for forwarded events)
    void ingest_xml(const std::string& xml);

    struct Stats {
        uint64_t events_received{0};
        uint64_t events_parsed{0};
        uint64_t events_produced{0};
        uint64_t parse_errors{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void collection_loop();
    void processing_loop();

    WinLogCollectorConfig config_;
    std::atomic<bool> running_{false};
    std::thread collection_thread_;
    std::thread processing_thread_;

    ConcurrentRingBuffer<std::string> ring_buffer_;
    ECSNormalizer normalizer_;
    std::unique_ptr<KafkaProducer> kafka_producer_;

    Counter* events_received_counter_{nullptr};
    Counter* events_parsed_counter_{nullptr};
    Counter* events_produced_counter_{nullptr};
    Counter* parse_error_counter_{nullptr};

    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace aiguard
