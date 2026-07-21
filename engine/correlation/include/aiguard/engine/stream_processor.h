#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_consumer.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/circular_buffer.h"
#include "aiguard/common/metrics.h"
#include "aiguard/common/thread_pool.h"
#include "aiguard/engine/event_windows.h"
#include "aiguard/engine/correlation_engine.h"

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <mutex>

namespace aiguard {

/// Stream processing configuration
struct StreamProcessorConfig {
    std::string kafka_brokers{"localhost:9092"};
    std::vector<std::string> input_topics{"aiguard-syslog", "aiguard-network", "aiguard-netflow", "aiguard-winlog"};
    std::string output_topic{"aiguard-alerts"};
    std::string group_id{"aiguard-engine"};
    size_t worker_threads{8};
    size_t batch_size{500};
    int poll_timeout_ms{100};
    bool enable_correlation{true};
    bool enable_windowing{true};
    size_t max_window_events{1000000};
    int correlation_timeout_ms{5000};
    int checkpoint_interval_ms{10000};
};

/// Core stream processing engine
///
/// Features:
/// - Lock-free ring buffers for event passing
/// - SIMD-optimized correlation (AVX-512)
/// - Stateful windowing (tumbling, sliding, session, hopping)
/// - Multi-threaded event processing
/// - Kafka input/output with exactly-once semantics
/// - Checkpointing for fault tolerance
class StreamProcessor {
public:
    explicit StreamProcessor(const StreamProcessorConfig& config);
    ~StreamProcessor();

    StreamProcessor(const StreamProcessor&) = delete;
    StreamProcessor& operator=(const StreamProcessor&) = delete;

    /// Start the stream processor
    bool start();

    /// Stop the stream processor
    void stop();

    /// Check if running
    [[nodiscard]] bool is_running() const { return running_.load(); }

    /// Register a correlation rule
    void add_correlation_rule(std::unique_ptr<CorrelationRule> rule);

    /// Register a window specification
    void add_window(const WindowSpec& spec);

    /// Get statistics
    struct Stats {
        uint64_t events_consumed{0};
        uint64_t events_processed{0};
        uint64_t alerts_generated{0};
        uint64_t correlation_matches{0};
        uint64_t current_eps{0};
        uint64_t peak_eps{0};
        double avg_processing_latency_ms{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void consume_loop();
    void process_loop();
    void checkpoint_loop();

    StreamProcessorConfig config_;
    std::atomic<bool> running_{false};

    std::unique_ptr<KafkaConsumer> consumer_;
    std::unique_ptr<KafkaProducer> alert_producer_;
    std::unique_ptr<CorrelationEngine> correlation_engine_;
    std::unique_ptr<EventWindowManager> window_manager_;
    std::unique_ptr<ThreadPool> thread_pool_;

    ConcurrentRingBuffer<std::unique_ptr<Event>> event_queue_;

    std::vector<std::thread> consumer_threads_;
    std::vector<std::thread> processor_threads_;
    std::thread checkpoint_thread_;

    // Metrics
    Counter* events_consumed_counter_{nullptr};
    Counter* events_processed_counter_{nullptr};
    Counter* alerts_generated_counter_{nullptr};
    Counter* correlation_matches_counter_{nullptr};
    Histogram* processing_latency_hist_{nullptr};

    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::chrono::steady_clock::time_point last_stats_time_;
    uint64_t last_events_consumed_{0};
};

} // namespace aiguard
