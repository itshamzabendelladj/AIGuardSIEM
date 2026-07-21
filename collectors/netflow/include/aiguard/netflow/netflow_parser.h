#pragma once

#include "aiguard/netflow/netflow_collector.h"
#include <string_view>
#include <optional>
#include <vector>
#include <cstdint>

namespace aiguard {

/// NetFlow v5 header
#pragma pack(push, 1)
struct NetFlowV5Header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
};
#pragma pack(pop)

/// NetFlow v5 record
#pragma pack(push, 1)
struct NetFlowV5Record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t first;
    uint32_t last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};
#pragma pack(pop)

/// NetFlow parser - parses v5, v9, and IPFIX
class NetFlowParser {
public:
    /// Parse a NetFlow packet
    static std::vector<NetFlowRecord> parse(const uint8_t* data, size_t len);

    /// Parse NetFlow v5
    static std::vector<NetFlowRecord> parse_v5(const uint8_t* data, size_t len);

    /// Parse NetFlow v9 (template-based)
    static std::vector<NetFlowRecord> parse_v9(const uint8_t* data, size_t len);

    /// Parse IPFIX
    static std::vector<NetFlowRecord> parse_ipfix(const uint8_t* data, size_t len);

    /// Convert IP address to string
    static std::string ip_to_string(uint32_t ip);

    /// Convert protocol number to string
    static std::string protocol_to_string(uint8_t proto);

    /// Parse TCP flags
    static std::string tcp_flags_to_string(uint8_t flags);
};

} // namespace aiguard
