#pragma once

#include "aiguard/common/event.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>
#include <optional>
#include <array>

namespace aiguard {

/// Flow key (5-tuple)
struct FlowKey {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    [[nodiscard]] size_t hash() const {
        size_t h = std::hash<uint32_t>{}(src_ip);
        h ^= std::hash<uint32_t>{}(dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

} // namespace aiguard

namespace std {
template<>
struct hash<aiguard::FlowKey> {
    size_t operator()(const aiguard::FlowKey& k) const {
        return k.hash();
    }
};
}

namespace aiguard {

/// Flow statistics
struct FlowStats {
    uint64_t packet_count{0};
    uint64_t byte_count{0};
    uint64_t fwd_packet_count{0};
    uint64_t bwd_packet_count{0};
    uint64_t fwd_byte_count{0};
    uint64_t bwd_byte_count{0};
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_time;

    // Flow duration
    int64_t duration_ms{0};

    // Packet size statistics
    double min_packet_size{0.0};
    double max_packet_size{0.0};
    double mean_packet_size{0.0};
    double std_packet_size{0.0};
    double var_packet_size{0.0};

    // Inter-arrival time statistics (microseconds)
    double min_iat{0.0};
    double max_iat{0.0};
    double mean_iat{0.0};
    double std_iat{0.0};

    // Forward direction statistics
    double fwd_min_pkt_size{0.0};
    double fwd_max_pkt_size{0.0};
    double fwd_mean_pkt_size{0.0};
    double fwd_std_pkt_size{0.0};
    double fwd_min_iat{0.0};
    double fwd_max_iat{0.0};
    double fwd_mean_iat{0.0};
    double fwd_std_iat{0.0};
    uint64_t fwd_psh_flags{0};
    uint64_t fwd_urg_flags{0};

    // Backward direction statistics
    double bwd_min_pkt_size{0.0};
    double bwd_max_pkt_size{0.0};
    double bwd_mean_pkt_size{0.0};
    double bwd_std_pkt_size{0.0};
    double bwd_min_iat{0.0};
    double bwd_max_iat{0.0};
    double bwd_mean_iat{0.0};
    double bwd_std_iat{0.0};
    uint64_t bwd_psh_flags{0};
    uint64_t bwd_urg_flags{0};

    // TCP flags
    uint64_t fin_count{0};
    uint64_t syn_count{0};
    uint64_t rst_count{0};
    uint64_t psh_count{0};
    uint64_t ack_count{0};
    uint64_t urg_count{0};
    uint64_t cwr_count{0};
    uint64_t ece_count{0};

    // Flag ratios
    double syn_flag_ratio{0.0};
    double rst_flag_ratio{0.0};
    double psh_flag_ratio{0.0};
    double ack_flag_ratio{0.0};

    // Flow bytes per second and packets per second
    double flow_bytes_per_second{0.0};
    double flow_packets_per_second{0.0};

    // Header length stats
    double min_header_len{0.0};
    double max_header_len{0.0};
    double mean_header_len{0.0};

    // Active/Idle time
    double active_min{0.0};
    double active_max{0.0};
    double active_mean{0.0};
    double active_std{0.0};
    double idle_min{0.0};
    double idle_max{0.0};
    double idle_mean{0.0};
    double idle_std{0.0};

    // Running sums for Welford's algorithm
    double pkt_size_running_var{0.0};
    double iat_running_var{0.0};
    double fwd_pkt_size_running_var{0.0};
    double bwd_pkt_size_running_var{0.0};
    double fwd_iat_running_var{0.0};
    double bwd_iat_running_var{0.0};
    uint64_t fwd_pkt_sizes_sum{0};
    uint64_t bwd_pkt_sizes_sum{0};
    double fwd_iat_sum{0.0};
    double bwd_iat_sum{0.0};
    int64_t last_fwd_time_us{0};
    int64_t last_bwd_time_us{0};
};

/// Active flow entry
struct FlowEntry {
    FlowKey key;
    FlowStats stats;
    std::vector<uint8_t> payload_samples;
    std::chrono::system_clock::time_point last_update;
    uint64_t total_packets{0};
    uint64_t total_bytes{0};
    bool is_forward{true};  // Direction of first packet
};

/// Flow tracker configuration
struct FlowTrackerConfig {
    int flow_timeout_seconds{120};      // Active flow timeout
    int idle_timeout_seconds{15};        // Idle flow timeout
    size_t max_flows{1000000};          // Maximum concurrent flows
    bool collect_payload_samples{false};
    size_t max_payload_sample_size{256};
    size_t payload_sample_interval{100};  // Sample every N packets
    bool export_expired_flows{true};
};

/// High-performance network flow tracker
///
/// Features:
/// - Bidirectional flow tracking
/// - CICFlowMeter-style 84+ flow features
/// - Welford's online algorithm for running statistics
/// - Flow expiration with timeout
/// - Thread-safe concurrent access
/// - Sub-microsecond per-packet processing
class FlowTracker {
public:
    explicit FlowTracker(const FlowTrackerConfig& config = {});
    ~FlowTracker() = default;

    /// Process a packet and update flow state
    /// @param data Packet data (starting from IP header)
    /// @param len Packet length
    /// @param timestamp Packet timestamp
    /// @return Flow key for this packet
    std::optional<FlowKey> process_packet(const uint8_t* data, size_t len,
                                           std::chrono::system_clock::time_point timestamp);

    /// Extract flow features for ML inference
    /// @param key Flow key
    /// @return Vector of 84+ flow features (CICFlowMeter style)
    std::vector<double> extract_features(const FlowKey& key) const;

    /// Get all active flow keys
    std::vector<FlowKey> get_active_flows() const;

    /// Get flow statistics for a specific flow
    std::optional<FlowStats> get_flow_stats(const FlowKey& key) const;

    /// Expire inactive flows
    /// @return Vector of expired flow entries
    std::vector<FlowEntry> expire_flows();

    /// Get number of active flows
    [[nodiscard]] size_t active_flow_count() const;

    /// Get flow tracker statistics
    struct Stats {
        uint64_t flows_created{0};
        uint64_t flows_expired{0};
        uint64_t packets_processed{0};
        uint64_t bytes_processed{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    /// Parse IP header and extract 5-tuple
    std::optional<FlowKey> parse_packet(const uint8_t* data, size_t len,
                                         std::chrono::system_clock::time_point timestamp,
                                         size_t& ip_header_len,
                                         size_t& transport_header_len);

    /// Update flow statistics with new packet
    void update_flow_stats(FlowEntry& entry, size_t packet_len,
                           std::chrono::system_clock::time_point timestamp,
                           bool is_forward, uint8_t tcp_flags);

    /// Welford's online algorithm for variance
    static void welford_update(double& mean, double& var, double value, uint64_t count);

    /// Calculate final statistics for expired flow
    void finalize_stats(FlowEntry& entry);

    /// Normalize flow key (ensure consistent direction)
    FlowKey normalize_key(const FlowKey& key, bool& is_forward);

    FlowTrackerConfig config_;
    std::unordered_map<FlowKey, FlowEntry> flows_;
    mutable std::mutex mutex_;
    Stats stats_;
};

} // namespace aiguard
