#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/ecs_schema.h"
#include "aiguard/common/metrics.h"
#include "aiguard/common/circular_buffer.h"
#include "aiguard/common/config.h"

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>

namespace aiguard {

/// NetFlow version
enum class NetFlowVersion {
    V5,
    V9,
    IPFIX
};

/// Parsed NetFlow record
struct NetFlowRecord {
    uint32_t src_addr{0};
    uint32_t dst_addr{0};
    uint32_t next_hop{0};
    uint16_t input_if{0};
    uint16_t output_if{0};
    uint32_t d_pkts{0};
    uint32_t d_octets{0};
    uint32_t first{0};    // SysUptime at start of flow
    uint32_t last{0};     // SysUptime at last packet
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};
    uint8_t tcp_flags{0};
    uint8_t tos{0};
    uint16_t src_as{0};
    uint16_t dst_as{0};
    uint8_t src_mask{0};
    uint8_t dst_mask{0};
    NetFlowVersion version{NetFlowVersion::V5};
};

/// NetFlow collector configuration
struct NetFlowCollectorConfig {
    uint16_t udp_port{2055};
    std::string bind_address{"0.0.0.0"};
    size_t buffer_size{65536};
    size_t worker_threads{2};
    size_t batch_size{500};
    int batch_timeout_ms{100};
    std::string kafka_brokers{"localhost:9092"};
    std::string kafka_topic{"aiguard-netflow"};
    size_t ring_buffer_capacity{262144};
    bool enable_metrics{true};
};

/// NetFlow/IPFIX collector
class NetFlowCollector {
public:
    explicit NetFlowCollector(const NetFlowCollectorConfig& config);
    ~NetFlowCollector();

    NetFlowCollector(const NetFlowCollector&) = delete;
    NetFlowCollector& operator=(const NetFlowCollector&) = delete;

    bool start();
    void stop();
    [[nodiscard]] bool is_running() const { return running_.load(); }

    struct Stats {
        uint64_t packets_received{0};
        uint64_t records_parsed{0};
        uint64_t parse_errors{0};
        uint64_t records_produced{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void receive_loop();
    void processing_loop();

    NetFlowCollectorConfig config_;
    std::atomic<bool> running_{false};
    int udp_socket_{-1};
    std::vector<std::thread> receiver_threads_;
    std::thread processing_thread_;

    ConcurrentRingBuffer<std::vector<uint8_t>> ring_buffer_;
    ECSNormalizer normalizer_;
    std::unique_ptr<KafkaProducer> kafka_producer_;

    Counter* packets_received_counter_{nullptr};
    Counter* records_parsed_counter_{nullptr};
    Counter* parse_error_counter_{nullptr};
    Counter* records_produced_counter_{nullptr};

    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace aiguard
