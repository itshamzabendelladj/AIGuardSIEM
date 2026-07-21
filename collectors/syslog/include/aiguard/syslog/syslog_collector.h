#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/ecs_schema.h"
#include "aiguard/common/metrics.h"
#include "aiguard/common/thread_pool.h"
#include "aiguard/common/circular_buffer.h"
#include "aiguard/common/config.h"

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <array>

namespace aiguard {

/// Syslog protocol transport
enum class SyslogTransport {
    UDP,
    TCP,
    TLS
};

/// Syslog facility codes (RFC 5424)
enum class SyslogFacility {
    Kernel = 0,     User = 1,        Mail = 2,        Daemon = 3,
    Auth = 4,       Syslog = 5,      LinePrinter = 6, News = 7,
    UUCP = 8,       Cron = 9,        AuthPriv = 10,   FTP = 11,
    NTP = 12,       Audit = 13,      Alert = 14,      Clock = 15,
    Local0 = 16,    Local1 = 17,     Local2 = 18,     Local3 = 19,
    Local4 = 20,    Local5 = 21,     Local6 = 22,     Local7 = 23
};

/// Syslog severity codes (RFC 5424)
enum class SyslogSeverity {
    Emergency = 0,  Alert = 1,       Critical = 2,    Error = 3,
    Warning = 4,    Notice = 5,      Informational = 6, Debug = 7
};

/// Parsed syslog message
struct SyslogMessage {
    int priority{0};           // facility * 8 + severity
    SyslogFacility facility{SyslogFacility::User};
    SyslogSeverity severity{SyslogSeverity::Informational};
    std::string timestamp;
    std::string hostname;
    std::string app_name;
    std::string proc_id;
    std::string msg_id;
    std::string message;
    std::string structured_data;  // RFC 5424 structured data
    std::string raw_message;
    int version{1};  // RFC 5424 version (0 for RFC 3164)
};

/// Syslog collector configuration
struct SyslogCollectorConfig {
    uint16_t udp_port{514};
    uint16_t tcp_port{514};
    uint16_t tls_port{6514};
    SyslogTransport transport{SyslogTransport::UDP};
    std::string bind_address{"0.0.0.0"};
    size_t buffer_size{65536};
    size_t worker_threads{4};
    size_t batch_size{1000};
    int batch_timeout_ms{100};
    bool enable_tls{false};
    std::string tls_cert_file;
    std::string tls_key_file;
    std::string tls_ca_file;
    std::string kafka_topic{"aiguard-syslog"};
    std::string kafka_brokers{"localhost:9092"};
    size_t ring_buffer_capacity{1048576};  // 1M events
    bool enable_metrics{true};
    int metrics_port{9100};
    size_t max_message_size{262144};  // 256KB
    int socket_receive_buffer_bytes{4194304};  // 4MB
    bool enable_non_blocking{true};
};

/// High-performance syslog collector
///
/// Supports:
/// - RFC 5424 and RFC 3164 syslog formats
/// - UDP, TCP, and TLS transports
/// - DPDK kernel bypass (optional)
/// - Zero-copy parsing
/// - Batched Kafka production
/// - 500,000+ EPS per node
class SyslogCollector {
public:
    explicit SyslogCollector(const SyslogCollectorConfig& config);
    ~SyslogCollector();

    SyslogCollector(const SyslogCollector&) = delete;
    SyslogCollector& operator=(const SyslogCollector&) = delete;

    /// Start the collector
    bool start();

    /// Stop the collector
    void stop();

    /// Check if collector is running
    [[nodiscard]] bool is_running() const { return running_.load(); }

    /// Get collector statistics
    struct Stats {
        uint64_t messages_received{0};
        uint64_t messages_parsed{0};
        uint64_t messages_produced{0};
        uint64_t parse_errors{0};
        uint64_t bytes_received{0};
        uint64_t current_eps{0};
        uint64_t peak_eps{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void udp_receive_loop();
    void tcp_accept_loop();
    void tcp_connection_handler(int client_fd);
    void tls_accept_loop();
    void processing_loop();
    void metrics_loop();

    SyslogCollectorConfig config_;
    std::atomic<bool> running_{false};

    // Network sockets
    int udp_socket_{-1};
    int tcp_socket_{-1};
    int tls_socket_{-1};

    // Threads
    std::vector<std::thread> receiver_threads_;
    std::thread processing_thread_;
    std::thread metrics_thread_;

    // Ring buffer for passing raw messages to processing thread
    struct RawMessage {
        std::vector<uint8_t> data;
        std::string source_ip;
        uint16_t source_port{0};
    };
    ConcurrentRingBuffer<RawMessage> ring_buffer_;

    // ECS normalizer
    ECSNormalizer normalizer_;

    // Kafka producer
    std::unique_ptr<KafkaProducer> kafka_producer_;

    // Metrics
    Counter* messages_received_counter_{nullptr};
    Counter* messages_parsed_counter_{nullptr};
    Counter* messages_produced_counter_{nullptr};
    Counter* parse_error_counter_{nullptr};
    Histogram* processing_latency_hist_{nullptr};
    Histogram* batch_size_hist_{nullptr};

    // Stats
    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::chrono::steady_clock::time_point last_stats_time_;
    uint64_t last_messages_received_{0};
};

} // namespace aiguard
