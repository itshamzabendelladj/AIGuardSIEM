#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <atomic>
#include <functional>
#include <mutex>

struct rd_kafka_t;
struct rd_kafka_topic_t;
struct rd_kafka_conf_s;

namespace aiguard {

/// Configuration for Kafka consumer
struct KafkaConsumerConfig {
    std::string brokers{"localhost:9092"};
    std::vector<std::string> topics{"aiguard-events"};
    std::string group_id{"aiguard-engine"};
    int session_timeout_ms{30000};
    int fetch_min_bytes{1};
    int fetch_max_bytes{52428800};  // 50MB
    int max_poll_records{500};
    int auto_offset_reset{1};  // 0=earliest, 1=latest
    bool enable_auto_commit{false};
    int auto_commit_interval_ms{5000};
    int partition_assignment_strategy{0};  // 0=range, 1=roundrobin
    std::string security_protocol{"PLAINTEXT"};
    std::string ssl_ca_location;
    std::string ssl_certificate_location;
    std::string ssl_key_location;
    std::string sasl_username;
    std::string sasl_password;
    std::string sasl_mechanism{"PLAIN"};
};

/// Consumed message
struct KafkaMessage {
    std::string topic;
    int partition{0};
    int64_t offset{0};
    std::string key;
    std::string payload;
    int64_t timestamp{0};
    int error_code{0};
    std::string error_string;
};

/// High-performance Kafka consumer with manual offset management
///
/// Features:
/// - Manual commit for exactly-once processing
/// - Batch consumption for throughput
/// - Rebalance callbacks
/// - Thread-safe poll loop
class KafkaConsumer {
public:
    using MessageCallback = std::function<void(const KafkaMessage&)>;
    using RebalanceCallback = std::function<void(rd_kafka_t*, int,
                                                   rd_kafka_topic_partition_list_t*)>;

    explicit KafkaConsumer(const KafkaConsumerConfig& config);
    ~KafkaConsumer();

    KafkaConsumer(const KafkaConsumer&) = delete;
    KafkaConsumer& operator=(const KafkaConsumer&) = delete;

    /// Subscribe to topics
    bool subscribe();

    /// Poll for a single message
    /// @param timeout_ms Poll timeout
    /// @return Optional message (nullopt on timeout)
    std::optional<KafkaMessage> poll(int timeout_ms = 100);

    /// Poll for a batch of messages
    /// @param max_messages Maximum messages to return
    /// @param timeout_ms Poll timeout
    /// @return Vector of messages
    std::vector<KafkaMessage> poll_batch(size_t max_messages, int timeout_ms = 100);

    /// Commit offsets synchronously
    bool commit_sync();

    /// Commit offsets asynchronously
    bool commit_async();

    /// Pause consumption on specific partitions
    void pause(const std::vector<std::pair<std::string, int>>& partitions);

    /// Resume consumption on specific partitions
    void resume(const std::vector<std::pair<std::string, int>>& partitions);

    /// Get consumer lag
    struct LagInfo {
        std::string topic;
        int partition;
        int64_t current_offset;
        int64_t log_end_offset;
        int64_t lag;
    };
    [[nodiscard]] std::vector<LagInfo> get_lag() const;

    /// Consumer statistics
    struct Stats {
        uint64_t messages_consumed{0};
        uint64_t bytes_consumed{0};
        uint64_t commit_count{0};
        uint64_t error_count{0};
    };
    [[nodiscard]] Stats get_stats() const;

    /// Close consumer
    void close();

private:
    static void rebalance_callback(rd_kafka_t* rk, int err,
                                    rd_kafka_topic_partition_list_t* partitions,
                                    void* opaque);

    KafkaConsumerConfig config_;
    rd_kafka_t* handle_{nullptr};
    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::atomic<bool> running_{false};
};

} // namespace aiguard
