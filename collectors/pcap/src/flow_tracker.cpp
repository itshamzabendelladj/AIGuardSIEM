#include "aiguard/pcap/flow_tracker.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <chrono>

namespace aiguard {

// IP header structure (packed)
#pragma pack(push, 1)
struct IPHeader {
    uint8_t version_ihl;     // Version (4 bits) + IHL (4 bits)
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};
#pragma pack(pop)

// TCP header structure (packed)
#pragma pack(push, 1)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;  // 4 bits offset, 4 bits reserved
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
#pragma pack(pop)

// UDP header structure (packed)
#pragma pack(push, 1)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

// Ethernet header
#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};
#pragma pack(pop)

static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_PSH = 0x08;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;
static constexpr uint8_t TCP_FLAG_URG = 0x20;
static constexpr uint8_t TCP_FLAG_ECE = 0x40;
static constexpr uint8_t TCP_FLAG_CWR = 0x80;

FlowTracker::FlowTracker(const FlowTrackerConfig& config)
    : config_(config) {
    flows_.reserve(config_.max_flows);
}

FlowKey FlowTracker::normalize_key(const FlowKey& key, bool& is_forward) {
    // Ensure consistent ordering: lower IP first
    if (key.src_ip < key.dst_ip ||
        (key.src_ip == key.dst_ip && key.src_port <= key.dst_port)) {
        is_forward = true;
        return key;
    } else {
        is_forward = false;
        FlowKey normalized;
        normalized.src_ip = key.dst_ip;
        normalized.dst_ip = key.src_ip;
        normalized.src_port = key.dst_port;
        normalized.dst_port = key.src_port;
        normalized.protocol = key.protocol;
        return normalized;
    }
}

std::optional<FlowKey> FlowTracker::parse_packet(const uint8_t* data, size_t len,
                                                   std::chrono::system_clock::time_point timestamp,
                                                   size_t& ip_header_len,
                                                   size_t& transport_header_len) {
    if (len < sizeof(EthernetHeader) + sizeof(IPHeader)) {
        return std::nullopt;
    }

    // Skip Ethernet header
    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t ethertype = ntohs(eth->ethertype);

    size_t ip_offset;
    if (ethertype == 0x0800) {  // IPv4
        ip_offset = sizeof(EthernetHeader);
    } else if (ethertype == 0x8100) {  // 802.1Q VLAN
        if (len < sizeof(EthernetHeader) + 4 + sizeof(IPHeader)) return std::nullopt;
        ip_offset = sizeof(EthernetHeader) + 4;
        // Re-read ethertype after VLAN tag
        uint16_t inner_ethertype = ntohs(*reinterpret_cast<const uint16_t*>(data + sizeof(EthernetHeader) + 2));
        if (inner_ethertype != 0x0800) return std::nullopt;
    } else {
        return std::nullopt;  // Not IPv4
    }

    if (ip_offset + sizeof(IPHeader) > len) return std::nullopt;

    const auto* ip = reinterpret_cast<const IPHeader*>(data + ip_offset);
    uint8_t version = (ip->version_ihl >> 4) & 0x0F;
    if (version != 4) return std::nullopt;  // Only IPv4

    ip_header_len = (ip->version_ihl & 0x0F) * 4;
    if (ip_header_len < 20) return std::nullopt;

    uint16_t total_length = ntohs(ip->total_length);
    if (total_length > len - ip_offset) {
        // Truncated packet, use available data
    }

    FlowKey key;
    key.src_ip = ip->src_addr;
    key.dst_ip = ip->dst_addr;
    key.protocol = ip->protocol;

    transport_header_len = 0;

    if (ip->protocol == 6) {  // TCP
        if (ip_offset + ip_header_len + sizeof(TCPHeader) > len) return std::nullopt;
        const auto* tcp = reinterpret_cast<const TCPHeader*>(data + ip_offset + ip_header_len);
        key.src_port = ntohs(tcp->src_port);
        key.dst_port = ntohs(tcp->dst_port);
        transport_header_len = (tcp->data_offset >> 4) * 4;
    } else if (ip->protocol == 17) {  // UDP
        if (ip_offset + ip_header_len + sizeof(UDPHeader) > len) return std::nullopt;
        const auto* udp = reinterpret_cast<const UDPHeader*>(data + ip_offset + ip_header_len);
        key.src_port = ntohs(udp->src_port);
        key.dst_port = ntohs(udp->dst_port);
        transport_header_len = sizeof(UDPHeader);
    } else {
        // Other protocols - no port numbers
        key.src_port = 0;
        key.dst_port = 0;
    }

    return key;
}

void FlowTracker::welford_update(double& mean, double& var, double value, uint64_t count) {
    double delta = value - mean;
    mean += delta / static_cast<double>(count);
    double delta2 = value - mean;
    var += delta * delta2;
}

void FlowTracker::update_flow_stats(FlowEntry& entry, size_t packet_len,
                                     std::chrono::system_clock::time_point timestamp,
                                     bool is_forward, uint8_t tcp_flags) {
    auto& s = entry.stats;
    auto time_us = std::chrono::duration_cast<std::chrono::microseconds>(
        timestamp.time_since_epoch()).count();

    s.packet_count++;
    s.byte_count += packet_len;
    entry.total_packets++;
    entry.total_bytes += packet_len;

    // Update packet size statistics (Welford's algorithm)
    if (s.packet_count == 1) {
        s.min_packet_size = s.max_packet_size = s.mean_packet_size = static_cast<double>(packet_len);
        s.pkt_size_running_var = 0.0;
    } else {
        if (packet_len < s.min_packet_size) s.min_packet_size = static_cast<double>(packet_len);
        if (packet_len > s.max_packet_size) s.max_packet_size = static_cast<double>(packet_len);
        welford_update(s.mean_packet_size, s.pkt_size_running_var,
                       static_cast<double>(packet_len), s.packet_count);
    }

    // Inter-arrival time
    if (s.packet_count > 1) {
        double iat = static_cast<double>(time_us - s.last_time.time_since_epoch().count() / 1000);
        if (s.packet_count == 2) {
            s.min_iat = s.max_iat = s.mean_iat = iat;
            s.iat_running_var = 0.0;
        } else {
            if (iat < s.min_iat) s.min_iat = iat;
            if (iat > s.max_iat) s.max_iat = iat;
            welford_update(s.mean_iat, s.iat_running_var, iat, s.packet_count - 1);
        }
    }

    // TCP flags
    if (tcp_flags & TCP_FLAG_FIN) s.fin_count++;
    if (tcp_flags & TCP_FLAG_SYN) s.syn_count++;
    if (tcp_flags & TCP_FLAG_RST) s.rst_count++;
    if (tcp_flags & TCP_FLAG_PSH) s.psh_count++;
    if (tcp_flags & TCP_FLAG_ACK) s.ack_count++;
    if (tcp_flags & TCP_FLAG_URG) s.urg_count++;
    if (tcp_flags & TCP_FLAG_ECE) s.ece_count++;
    if (tcp_flags & TCP_FLAG_CWR) s.cwr_count++;

    // Directional statistics
    if (is_forward) {
        s.fwd_packet_count++;
        s.fwd_byte_count += packet_len;

        if (s.fwd_packet_count == 1) {
            s.fwd_min_pkt_size = s.fwd_max_pkt_size = s.fwd_mean_pkt_size = static_cast<double>(packet_len);
            s.fwd_pkt_size_running_var = 0.0;
        } else {
            if (packet_len < s.fwd_min_pkt_size) s.fwd_min_pkt_size = static_cast<double>(packet_len);
            if (packet_len > s.fwd_max_pkt_size) s.fwd_max_pkt_size = static_cast<double>(packet_len);
            welford_update(s.fwd_mean_pkt_size, s.fwd_pkt_size_running_var,
                           static_cast<double>(packet_len), s.fwd_packet_count);
        }

        if (tcp_flags & TCP_FLAG_PSH) s.fwd_psh_flags++;
        if (tcp_flags & TCP_FLAG_URG) s.fwd_urg_flags++;

        // Forward IAT
        if (s.fwd_packet_count > 1 && s.last_fwd_time_us > 0) {
            double fwd_iat = static_cast<double>(time_us - s.last_fwd_time_us);
            if (s.fwd_packet_count == 2) {
                s.fwd_min_iat = s.fwd_max_iat = s.fwd_mean_iat = fwd_iat;
                s.fwd_iat_running_var = 0.0;
            } else {
                if (fwd_iat < s.fwd_min_iat) s.fwd_min_iat = fwd_iat;
                if (fwd_iat > s.fwd_max_iat) s.fwd_max_iat = fwd_iat;
                welford_update(s.fwd_mean_iat, s.fwd_iat_running_var,
                               fwd_iat, s.fwd_packet_count - 1);
            }
        }
        s.last_fwd_time_us = time_us;
    } else {
        s.bwd_packet_count++;
        s.bwd_byte_count += packet_len;

        if (s.bwd_packet_count == 1) {
            s.bwd_min_pkt_size = s.bwd_max_pkt_size = s.bwd_mean_pkt_size = static_cast<double>(packet_len);
            s.bwd_pkt_size_running_var = 0.0;
        } else {
            if (packet_len < s.bwd_min_pkt_size) s.bwd_min_pkt_size = static_cast<double>(packet_len);
            if (packet_len > s.bwd_max_pkt_size) s.bwd_max_pkt_size = static_cast<double>(packet_len);
            welford_update(s.bwd_mean_pkt_size, s.bwd_pkt_size_running_var,
                           static_cast<double>(packet_len), s.bwd_packet_count);
        }

        if (tcp_flags & TCP_FLAG_PSH) s.bwd_psh_flags++;
        if (tcp_flags & TCP_FLAG_URG) s.bwd_urg_flags++;

        // Backward IAT
        if (s.bwd_packet_count > 1 && s.last_bwd_time_us > 0) {
            double bwd_iat = static_cast<double>(time_us - s.last_bwd_time_us);
            if (s.bwd_packet_count == 2) {
                s.bwd_min_iat = s.bwd_max_iat = s.bwd_mean_iat = bwd_iat;
                s.bwd_iat_running_var = 0.0;
            } else {
                if (bwd_iat < s.bwd_min_iat) s.bwd_min_iat = bwd_iat;
                if (bwd_iat > s.bwd_max_iat) s.bwd_max_iat = bwd_iat;
                welford_update(s.bwd_mean_iat, s.bwd_iat_running_var,
                               bwd_iat, s.bwd_packet_count - 1);
            }
        }
        s.last_bwd_time_us = time_us;
    }

    s.last_time = timestamp;
}

void FlowTracker::finalize_stats(FlowEntry& entry) {
    auto& s = entry.stats;

    // Compute standard deviations
    if (s.packet_count > 1) {
        s.std_packet_size = std::sqrt(s.pkt_size_running_var / (s.packet_count - 1));
        s.var_packet_size = s.pkt_size_running_var / (s.packet_count - 1);
    }
    if (s.packet_count > 2) {
        s.std_iat = std::sqrt(s.iat_running_var / (s.packet_count - 2));
    }
    if (s.fwd_packet_count > 1) {
        s.fwd_std_pkt_size = std::sqrt(s.fwd_pkt_size_running_var / (s.fwd_packet_count - 1));
    }
    if (s.bwd_packet_count > 1) {
        s.bwd_std_pkt_size = std::sqrt(s.bwd_pkt_size_running_var / (s.bwd_packet_count - 1));
    }
    if (s.fwd_packet_count > 2) {
        s.fwd_std_iat = std::sqrt(s.fwd_iat_running_var / (s.fwd_packet_count - 2));
    }
    if (s.bwd_packet_count > 2) {
        s.bwd_std_iat = std::sqrt(s.bwd_iat_running_var / (s.bwd_packet_count - 2));
    }

    // Flow duration
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        s.last_time - s.start_time);
    s.duration_ms = duration.count();

    // Rates
    if (s.duration_ms > 0) {
        s.flow_bytes_per_second = (s.byte_count * 1000.0) / s.duration_ms;
        s.flow_packets_per_second = (s.packet_count * 1000.0) / s.duration_ms;
    }

    // Flag ratios
    if (s.packet_count > 0) {
        s.syn_flag_ratio = static_cast<double>(s.syn_count) / s.packet_count;
        s.rst_flag_ratio = static_cast<double>(s.rst_count) / s.packet_count;
        s.psh_flag_ratio = static_cast<double>(s.psh_count) / s.packet_count;
        s.ack_flag_ratio = static_cast<double>(s.ack_count) / s.packet_count;
    }

    // Header length
    double total_header = static_cast<double>(s.byte_count - 
        (s.fwd_byte_count - s.fwd_packet_count * 20) - 
        (s.bwd_byte_count - s.bwd_packet_count * 20));
    s.mean_header_len = s.packet_count > 0 ? total_header / s.packet_count : 0;
}

std::optional<FlowKey> FlowTracker::process_packet(const uint8_t* data, size_t len,
                                                     std::chrono::system_clock::time_point timestamp) {
    size_t ip_header_len = 0;
    size_t transport_header_len = 0;

    auto key = parse_packet(data, len, timestamp, ip_header_len, transport_header_len);
    if (!key) return std::nullopt;

    bool is_forward;
    auto normalized = normalize_key(*key, is_forward);

    // Extract TCP flags
    uint8_t tcp_flags = 0;
    if (key->protocol == 6) {
        size_t ip_offset = sizeof(EthernetHeader);
        // Handle VLAN
        const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
        if (ntohs(eth->ethertype) == 0x8100) {
            ip_offset += 4;
        }
        const auto* ip = reinterpret_cast<const IPHeader*>(data + ip_offset);
        ip_header_len = (ip->version_ihl & 0x0F) * 4;
        if (ip_offset + ip_header_len + sizeof(TCPHeader) <= len) {
            const auto* tcp = reinterpret_cast<const TCPHeader*>(data + ip_offset + ip_header_len);
            tcp_flags = tcp->flags;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(normalized);
    if (it == flows_.end()) {
        // Create new flow
        if (flows_.size() >= config_.max_flows) {
            spdlog::warn("Max flows reached ({}), evicting oldest", config_.max_flows);
            // Simple eviction: remove first flow
            flows_.erase(flows_.begin());
        }

        FlowEntry entry;
        entry.key = normalized;
        entry.stats.start_time = timestamp;
        entry.is_forward = is_forward;
        update_flow_stats(entry, len, timestamp, is_forward, tcp_flags);
        flows_.emplace(normalized, std::move(entry));
        stats_.flows_created++;
    } else {
        update_flow_stats(it->second, len, timestamp, is_forward, tcp_flags);
    }

    stats_.packets_processed++;
    stats_.bytes_processed += len;

    return normalized;
}

std::vector<double> FlowTracker::extract_features(const FlowKey& key) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(key);
    if (it == flows_.end()) return {};

    const auto& s = it->second.stats;

    // 84 CICFlowMeter-style features
    return {
        static_cast<double>(s.duration_ms),            // 1. Flow Duration
        // Forward packet stats
        s.fwd_mean_pkt_size,                            // 2. Fwd Packet Length Mean
        s.fwd_std_pkt_size,                             // 3. Fwd Packet Length Std
        s.fwd_max_pkt_size,                             // 4. Fwd Packet Length Max
        s.fwd_min_pkt_size,                             // 5. Fwd Packet Length Min
        // Backward packet stats
        s.bwd_mean_pkt_size,                            // 6. Bwd Packet Length Mean
        s.bwd_std_pkt_size,                             // 7. Bwd Packet Length Std
        s.bwd_max_pkt_size,                             // 8. Bwd Packet Length Max
        s.bwd_min_pkt_size,                             // 9. Bwd Packet Length Min
        // Flow bytes/s, packets/s
        s.flow_bytes_per_second,                        // 10. Flow Bytes/s
        s.flow_packets_per_second,                      // 11. Flow Packets/s
        // Flow IAT stats
        s.min_iat,                                      // 12. Flow IAT Min
        s.max_iat,                                      // 13. Flow IAT Max
        s.mean_iat,                                     // 14. Flow IAT Mean
        s.std_iat,                                      // 15. Flow IAT Std
        // Forward IAT stats
        s.fwd_min_iat,                                  // 16. Fwd IAT Min
        s.fwd_max_iat,                                  // 17. Fwd IAT Max
        s.fwd_mean_iat,                                 // 18. Fwd IAT Mean
        s.fwd_std_iat,                                  // 19. Fwd IAT Std
        // Backward IAT stats
        s.bwd_min_iat,                                  // 20. Bwd IAT Min
        s.bwd_max_iat,                                  // 21. Bwd IAT Max
        s.bwd_mean_iat,                                 // 22. Bwd IAT Mean
        s.bwd_std_iat,                                  // 23. Bwd IAT Std
        // Packet stats overall
        s.mean_packet_size,                             // 24. Packet Length Mean
        s.std_packet_size,                              // 25. Packet Length Std
        s.var_packet_size,                              // 26. Packet Length Variance
        s.max_packet_size,                              // 27. Packet Length Max
        s.min_packet_size,                              // 28. Packet Length Min
        // Flag counts
        static_cast<double>(s.fin_count),               // 29. FIN Flag Count
        static_cast<double>(s.syn_count),               // 30. SYN Flag Count
        static_cast<double>(s.rst_count),               // 31. RST Flag Count
        static_cast<double>(s.psh_count),               // 32. PSH Flag Count
        static_cast<double>(s.ack_count),               // 33. ACK Flag Count
        static_cast<double>(s.urg_count),               // 34. URG Flag Count
        static_cast<double>(s.cwr_count),               // 35. CWR Flag Count
        static_cast<double>(s.ece_count),               // 36. ECE Flag Count
        // Flag ratios
        s.syn_flag_ratio,                               // 37. SYN Flag Rate
        s.rst_flag_ratio,                               // 38. RST Flag Rate
        s.psh_flag_ratio,                               // 39. PSH Flag Rate
        s.ack_flag_ratio,                               // 40. ACK Flag Rate
        // Direction counts
        static_cast<double>(s.fwd_packet_count),        // 41. Total Fwd Packets
        static_cast<double>(s.bwd_packet_count),        // 42. Total Bwd Packets
        static_cast<double>(s.fwd_byte_count),          // 43. Total Fwd Bytes
        static_cast<double>(s.bwd_byte_count),          // 44. Total Bwd Bytes
        // PSH/URG flags directional
        static_cast<double>(s.fwd_psh_flags),           // 45. Fwd PSH Flags
        static_cast<double>(s.bwd_psh_flags),           // 46. Bwd PSH Flags
        static_cast<double>(s.fwd_urg_flags),           // 47. Fwd URG Flags
        static_cast<double>(s.bwd_urg_flags),           // 48. Bwd URG Flags
        // Packet per second directional
        s.duration_ms > 0 ? (s.fwd_packet_count * 1000.0 / s.duration_ms) : 0.0,  // 49. Fwd Packets/s
        s.duration_ms > 0 ? (s.bwd_packet_count * 1000.0 / s.duration_ms) : 0.0,  // 50. Bwd Packets/s
        // Bytes per second directional
        s.duration_ms > 0 ? (s.fwd_byte_count * 1000.0 / s.duration_ms) : 0.0,    // 51. Fwd Bytes/s
        s.duration_ms > 0 ? (s.bwd_byte_count * 1000.0 / s.duration_ms) : 0.0,    // 52. Bwd Bytes/s
        // Min/Max packet length ratio
        s.max_packet_size > 0 ? s.min_packet_size / s.max_packet_size : 0.0,      // 53. Packet Length Min/Max
        // Flow bytes/packets total
        static_cast<double>(s.byte_count),              // 54. Total Bytes
        static_cast<double>(s.packet_count),            // 55. Total Packets
        // Down/Up ratio
        s.fwd_packet_count > 0 ?
            static_cast<double>(s.bwd_packet_count) / s.fwd_packet_count : 0.0,   // 56. Down/Up Ratio
        // Average packet size
        s.packet_count > 0 ? static_cast<double>(s.byte_count) / s.packet_count : 0.0, // 57. Avg Packet Size
        // Fwd/Bwd packet size ratios
        s.bwd_mean_pkt_size > 0 ? s.fwd_mean_pkt_size / s.bwd_mean_pkt_size : 0.0,  // 58. Fwd/Bwd Packet Size Ratio
        // Fwd/Bwd packet count ratio
        s.bwd_packet_count > 0 ?
            static_cast<double>(s.fwd_packet_count) / s.bwd_packet_count : 0.0,   // 59. Fwd/Bwd Packet Ratio
        // Fwd/Bwd byte ratio
        s.bwd_byte_count > 0 ?
            static_cast<double>(s.fwd_byte_count) / s.bwd_byte_count : 0.0,       // 60. Fwd/Bwd Byte Ratio
        // Header length stats
        s.mean_header_len,                               // 61. Avg Header Length
        s.min_header_len,                                // 62. Min Header Length
        s.max_header_len,                                // 63. Max Header Length
        // Active/Idle time
        s.active_min,                                    // 64. Active Min
        s.active_max,                                    // 65. Active Max
        s.active_mean,                                   // 66. Active Mean
        s.active_std,                                    // 67. Active Std
        s.idle_min,                                      // 68. Idle Min
        s.idle_max,                                      // 69. Idle Max
        s.idle_mean,                                     // 70. Idle Mean
        s.idle_std,                                      // 71. Idle Std
        // Additional features
        s.fwd_max_pkt_size > 0 ? s.fwd_min_pkt_size / s.fwd_max_pkt_size : 0.0,   // 72. Fwd Packet Length Min/Max
        s.bwd_max_pkt_size > 0 ? s.bwd_min_pkt_size / s.bwd_max_pkt_size : 0.0,   // 73. Bwd Packet Length Min/Max
        // Subflow stats (packet count in first 1s)
        static_cast<double>(s.packet_count),             // 74. Subflow Fwd Packets
        static_cast<double>(s.packet_count),             // 75. Subflow Bwd Packets
        // Window sizes (placeholder - would need TCP header parsing)
        0.0,                                             // 76. Fwd Window Min
        0.0,                                             // 77. Fwd Window Max
        0.0,                                             // 78. Fwd Window Mean
        0.0,                                             // 79. Bwd Window Min
        0.0,                                             // 80. Bwd Window Max
        0.0,                                             // 81. Bwd Window Mean
        // Total header bytes
        s.mean_header_len * s.packet_count,              // 82. Total Header Bytes
        // Init_Win_bytes (first packet window)
        0.0,                                             // 83. Init_Win_bytes
        // Protocol
        static_cast<double>(key.protocol),               // 84. Protocol
    };
}

std::vector<FlowKey> FlowTracker::get_active_flows() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FlowKey> keys;
    keys.reserve(flows_.size());
    for (const auto& [key, _] : flows_) {
        keys.push_back(key);
    }
    return keys;
}

std::optional<FlowStats> FlowTracker::get_flow_stats(const FlowKey& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flows_.find(key);
    if (it == flows_.end()) return std::nullopt;
    return it->second.stats;
}

std::vector<FlowEntry> FlowTracker::expire_flows() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FlowEntry> expired;
    auto now = std::chrono::system_clock::now();
    auto active_timeout = std::chrono::seconds(config_.flow_timeout_seconds);
    auto idle_timeout = std::chrono::seconds(config_.idle_timeout_seconds);

    for (auto it = flows_.begin(); it != flows_.end();) {
        const auto& entry = it->second;
        auto age = now - entry.stats.start_time;
        auto idle = now - entry.stats.last_time;

        if (age > active_timeout || idle > idle_timeout) {
            finalize_stats(it->second);
            expired.push_back(std::move(it->second));
            it = flows_.erase(it);
            stats_.flows_expired++;
        } else {
            ++it;
        }
    }

    return expired;
}

size_t FlowTracker::active_flow_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

FlowTracker::Stats FlowTracker::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

} // namespace aiguard
