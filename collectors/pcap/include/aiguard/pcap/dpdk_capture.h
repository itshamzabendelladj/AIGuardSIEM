#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/circular_buffer.h"
#include "aiguard/common/metrics.h"
#include "aiguard/pcap/flow_tracker.h"

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>

namespace aiguard {

/// Packet capture mode
enum class CaptureMode {
    LibPcap,    // Standard libpcap
    DPDK,       // DPDK kernel bypass
    AF_PACKET,  // Linux raw socket
    PF_RING     // PF_RING zero-copy
};

/// Packet capture configuration
struct PacketCaptureConfig {
    CaptureMode mode{CaptureMode::LibPcap};
    std::string interface{"eth0"};
    std::string bpf_filter;          // BPF filter expression
    int snapshot_length{65535};      // Snap length
    bool promiscuous_mode{true};
    int buffer_timeout_ms{100};
    size_t ring_buffer_capacity{262144};  // 256K packets
    size_t worker_threads{4};
    size_t batch_size{500};
    int batch_timeout_ms{50};
    std::string kafka_brokers{"localhost:9092"};
    std::string kafka_topic{"aiguard-network"};
    bool extract_flows{true};
    bool extract_payload{false};
    size_t max_payload_extract{256};
    bool enable_metrics{true};
    // DPDK-specific
    std::vector<std::string> dpdk_args;
    size_t dpdk_ring_size{4096};
    size_t dpdk_burst_size{32};
    size_t dpdk_mempool_size{262144};
    size_t dpdk_mempool_cache_size{512};
};

/// Raw packet structure
struct RawPacket {
    std::vector<uint8_t> data;
    std::chrono::system_clock::time_point timestamp;
    size_t original_length{0};
    int link_type{1};  // DLT_EN10MB
};

/// High-performance packet capture engine
///
/// Supports:
/// - libpcap for standard capture
/// - DPDK for 10Gbps+ line rate
/// - AF_PACKET for Linux raw sockets
/// - PF_RING for zero-copy
/// - Real-time flow tracking
/// - BPF filtering
class PacketCapture {
public:
    explicit PacketCapture(const PacketCaptureConfig& config);
    ~PacketCapture();

    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    /// Start capture
    bool start();

    /// Stop capture
    void stop();

    /// Check if running
    [[nodiscard]] bool is_running() const { return running_.load(); }

    /// Get statistics
    struct Stats {
        uint64_t packets_captured{0};
        uint64_t packets_dropped{0};
        uint64_t bytes_captured{0};
        uint64_t flows_active{0};
        uint64_t flows_expired{0};
        uint64_t current_pps{0};
        uint64_t peak_pps{0};
        double current_bps{0.0};
        double peak_bps{0.0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void pcap_capture_loop();
    void dpdk_capture_loop();
    void af_packet_capture_loop();
    void processing_loop();
    void flow_expiry_loop();
    void metrics_loop();

    PacketCaptureConfig config_;
    std::atomic<bool> running_{false};

    ConcurrentRingBuffer<RawPacket> ring_buffer_;

    std::vector<std::thread> capture_threads_;
    std::thread processing_thread_;
    std::thread flow_expiry_thread_;
    std::thread metrics_thread_;

    std::unique_ptr<KafkaProducer> kafka_producer_;
    std::unique_ptr<FlowTracker> flow_tracker_;

    // Metrics
    Counter* packets_captured_counter_{nullptr};
    Counter* packets_dropped_counter_{nullptr};
    Counter* bytes_captured_counter_{nullptr};
    Counter* flows_expired_counter_{nullptr};
    Histogram* capture_latency_hist_{nullptr};
    Histogram* packet_size_hist_{nullptr};

    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::chrono::steady_clock::time_point last_stats_time_;
    uint64_t last_packets_{0};
    uint64_t last_bytes_{0};

    // libpcap handle
    void* pcap_handle_{nullptr};  // pcap_t*
};

} // namespace aiguard
