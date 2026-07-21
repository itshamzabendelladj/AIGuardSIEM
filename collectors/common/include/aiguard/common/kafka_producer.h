#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <atomic>
#include <mutex>
#include <functional>
#include <chrono>

struct rd_kafka_t;
struct rd_kafka_topic_t;
struct rd_kafka_conf_s;

namespace aiguard {

/// Configuration for Kafka producer
struct KafkaProducerConfig {
    std::string brokers{"localhost:9092"};
    std::string topic{"aiguard-events"};
    int partition{RD_KAFKA_PARTITION_UA};  // unspecified partition
    int flush_timeout_ms{5000};
    int message_timeout_ms{10000};
    int queue_buffering_max_messages{100000};
    int queue_buffering_max_kbytes{1048576};  // 1MB
    int queue_buffering_max_ms{5};  // batch latency
    bool enable_idempotence{true};
    int compression_type{1};  // 1=snappy, 2=lz4, 3=zstd
    int batch_num_messages{10000};
    int message_max_bytes{1000000};
    int64_t message_send_max_retries{3};
    int request_required_acks{-1};  // all ISR
    std::string security_protocol{"PLAINTEXT"};
    std::string ssl_ca_location;
    std::string ssl_certificate_location;
    std::string ssl_key_location;
    std::string sasl_username;
    std::string sasl_password;
    std::string sasl_mechanism{"PLAIN"};
};

/// Delivery report callback data
struct DeliveryReport {
    std::string topic;
    int partition{0};
    int64_t offset{0};
    int error_code{0};
    std::string error_string;
    std::chrono::system_clock::time_point timestamp;
};

/// High-performance Kafka producer with batching and compression
///
/// Features:
/// - Idempotent producer for exactly-once semantics
/// - Configurable compression (snappy, lz4, zstd)
/// - Batch buffering with configurable latency
/// - Delivery report callbacks
/// - Thread-safe for concurrent produce calls
/// - Automatic retry with exponential backoff
class KafkaProducer {
public:
    using DeliveryCallback = std::function<void(const DeliveryReport&)>;

    explicit KafkaProducer(const KafkaProducerConfig& config);
    ~KafkaProducer();

    KafkaProducer(const KafkaProducer&) = delete;
    KafkaProducer& operator=(const KafkaProducer&) = delete;
    KafkaProducer(KafkaProducer&&) = delete;
    KafkaProducer& operator=(KafkaProducer&&) = delete;

    /// Produce a single message
    /// @param payload Message payload
    /// @param key Optional partitioning key
    /// @return true if message was queued successfully
    bool produce(std::string_view payload, std::string_view key = "");

    /// Produce a batch of messages
    /// @param payloads Vector of payload/key pairs
    /// @return Number of messages successfully queued
    size_t produce_batch(const std::vector<std::pair<std::string_view, std::string_view>>& payloads);

    /// Flush pending messages
    /// @param timeout_ms Timeout in milliseconds
    /// @return RD_KAFKA_CONF_OK on success
    int flush(int timeout_ms = -1);

    /// Poll for delivery reports
    /// @param timeout_ms Poll timeout
    /// @return Number of events served
    int poll(int timeout_ms = 0);

    /// Get the number of messages waiting in queue
    [[nodiscard]] size_t queue_size() const;

    /// Get producer statistics
    struct Stats {
        uint64_t messages_produced{0};
        uint64_t messages_delivered{0};
        uint64_t messages_failed{0};
        uint64_t bytes_produced{0};
        uint64_t avg_latency_us{0};
    };
    [[nodiscard]] Stats get_stats() const;

    /// Set delivery callback
    void set_delivery_callback(DeliveryCallback callback);

    /// Check if producer is healthy
    [[nodiscard]] bool is_healthy() const;

private:
    static void delivery_report_callback(rd_kafka_t* rk, void* payload,
                                          size_t len, int error_code,
                                          void* opaque, void* msg_opaque);

    KafkaProducerConfig config_;
    rd_kafka_t* handle_{nullptr};
    rd_kafka_topic_t* topic_{nullptr};
    DeliveryCallback delivery_callback_;
    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::atomic<bool> healthy_{false};
};

} // namespace aiguard
