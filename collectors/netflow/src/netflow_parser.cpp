#include "aiguard/netflow/netflow_parser.h"
#include <spdlog/spdlog.h>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>

namespace aiguard {

std::vector<NetFlowRecord> NetFlowParser::parse(const uint8_t* data, size_t len) {
    if (len < 2) return {};

    uint16_t version;
    std::memcpy(&version, data, sizeof(version));
    version = ntohs(version);

    switch (version) {
        case 5:
            return parse_v5(data, len);
        case 9:
            return parse_v9(data, len);
        case 10:
            return parse_ipfix(data, len);
        default:
            spdlog::warn("Unknown NetFlow version: {}", version);
            return {};
    }
}

std::vector<NetFlowRecord> NetFlowParser::parse_v5(const uint8_t* data, size_t len) {
    if (len < sizeof(NetFlowV5Header)) return {};

    auto* header = reinterpret_cast<const NetFlowV5Header*>(data);
    uint16_t count = ntohs(header->count);

    std::vector<NetFlowRecord> records;
    records.reserve(count);

    size_t offset = sizeof(NetFlowV5Header);
    for (uint16_t i = 0; i < count; ++i) {
        if (offset + sizeof(NetFlowV5Record) > len) break;

        auto* rec = reinterpret_cast<const NetFlowV5Record*>(data + offset);

        NetFlowRecord record;
        record.src_addr = rec->srcaddr;
        record.dst_addr = rec->dstaddr;
        record.next_hop = rec->nexthop;
        record.input_if = ntohs(rec->input);
        record.output_if = ntohs(rec->output);
        record.d_pkts = ntohl(rec->dPkts);
        record.d_octets = ntohl(rec->dOctets);
        record.first = ntohl(rec->first);
        record.last = ntohl(rec->last);
        record.src_port = ntohs(rec->srcport);
        record.dst_port = ntohs(rec->dstport);
        record.protocol = rec->prot;
        record.tcp_flags = rec->tcp_flags;
        record.tos = rec->tos;
        record.src_as = ntohs(rec->src_as);
        record.dst_as = ntohs(rec->dst_as);
        record.src_mask = rec->src_mask;
        record.dst_mask = rec->dst_mask;
        record.version = NetFlowVersion::V5;

        records.push_back(record);
        offset += sizeof(NetFlowV5Record);
    }

    return records;
}

std::vector<NetFlowRecord> NetFlowParser::parse_v9(const uint8_t* data, size_t len) {
    if (len < 20) return {};

    // v9 header
    uint16_t version, count;
    std::memcpy(&version, data, 2); version = ntohs(version);
    std::memcpy(&count, data + 2, 2); count = ntohs(count);

    uint32_t sys_uptime, unix_secs, flow_sequence;
    std::memcpy(&sys_uptime, data + 4, 4); sys_uptime = ntohl(sys_uptime);
    std::memcpy(&unix_secs, data + 8, 4); unix_secs = ntohl(unix_secs);
    std::memcpy(&flow_sequence, data + 12, 4); flow_sequence = ntohl(flow_sequence);

    uint32_t source_id;
    std::memcpy(&source_id, data + 16, 4); source_id = ntohl(source_id);

    // Template cache (in production this would be persistent)
    static thread_local std::unordered_map<uint16_t, std::vector<std::pair<uint16_t, uint16_t>>> templates;

    std::vector<NetFlowRecord> records;
    size_t offset = 20;

    int flow_set_count = 0;
    while (offset + 4 <= len && flow_set_count < count) {
        uint16_t flowset_id, flowset_len;
        std::memcpy(&flowset_id, data + offset, 2); flowset_id = ntohs(flowset_id);
        std::memcpy(&flowset_len, data + offset + 2, 2); flowset_len = ntohs(flowset_len);

        if (offset + flowset_len > len) break;

        if (flowset_id == 0) {
            // Template flowset
            size_t tpl_offset = offset + 4;
            while (tpl_offset + 4 <= offset + flowset_len) {
                uint16_t template_id, field_count;
                std::memcpy(&template_id, data + tpl_offset, 2); template_id = ntohs(template_id);
                std::memcpy(&field_count, data + tpl_offset + 2, 2); field_count = ntohs(field_count);
                tpl_offset += 4;

                std::vector<std::pair<uint16_t, uint16_t>> fields;
                for (uint16_t f = 0; f < field_count && tpl_offset + 4 <= offset + flowset_len; ++f) {
                    uint16_t field_type, field_len;
                    std::memcpy(&field_type, data + tpl_offset, 2); field_type = ntohs(field_type);
                    std::memcpy(&field_len, data + tpl_offset + 2, 2); field_len = ntohs(field_len);
                    fields.emplace_back(field_type, field_len);
                    tpl_offset += 4;
                }
                templates[template_id] = std::move(fields);
            }
        } else if (flowset_id == 1) {
            // Options template - skip for now
        } else if (flowset_id >= 256) {
            // Data flowset
            auto tpl_it = templates.find(flowset_id);
            if (tpl_it == templates.end()) {
                // No template yet - skip
            } else {
                const auto& fields = tpl_it->second;
                size_t record_offset = offset + 4;
                size_t record_size = 0;
                for (const auto& [type, flen] : fields) record_size += flen;

                while (record_offset + record_size <= offset + flowset_len) {
                    NetFlowRecord record;
                    record.version = NetFlowVersion::V9;
                    size_t field_offset = record_offset;

                    for (const auto& [field_type, field_len] : fields) {
                        if (field_offset + field_len > offset + flowset_len) break;

                        auto read_uint = [&](size_t flen) -> uint32_t {
                            uint32_t val = 0;
                            std::memcpy(&val, data + field_offset, flen);
                            switch (flen) {
                                case 1: return val & 0xFF;
                                case 2: return ntohs(val & 0xFFFF);
                                case 4: return ntohl(val);
                                default: return val;
                            }
                        };

                        switch (field_type) {
                            case 1:  // IN_BYTES
                                record.d_octets = read_uint(field_len);
                                break;
                            case 2:  // IN_PKTS
                                record.d_pkts = read_uint(field_len);
                                break;
                            case 4:  // PROTOCOL
                                record.protocol = data[field_offset];
                                break;
                            case 6:  // TCP_FLAGS
                                record.tcp_flags = data[field_offset];
                                break;
                            case 7:  // L4_SRC_PORT
                                record.src_port = read_uint(field_len) & 0xFFFF;
                                break;
                            case 8:  // IPV4_SRC_ADDR
                                std::memcpy(&record.src_addr, data + field_offset, 4);
                                break;
                            case 10: // L4_DST_PORT
                                record.dst_port = read_uint(field_len) & 0xFFFF;
                                break;
                            case 11: // IPV4_DST_ADDR
                                std::memcpy(&record.dst_addr, data + field_offset, 4);
                                break;
                            case 12: // OUT_BYTES
                                record.d_octets = read_uint(field_len);
                                break;
                            case 22: // SRC_AS
                                record.src_as = read_uint(field_len) & 0xFFFF;
                                break;
                            case 23: // DST_TOS
                                record.tos = data[field_offset];
                                break;
                            default:
                                break;
                        }
                        field_offset += field_len;
                    }

                    records.push_back(record);
                    record_offset += record_size;
                    flow_set_count++;
                }
            }
        }

        offset += flowset_len;
    }

    return records;
}

std::vector<NetFlowRecord> NetFlowParser::parse_ipfix(const uint8_t* data, size_t len) {
    if (len < 16) return {};

    // IPFIX header
    uint16_t version, length;
    std::memcpy(&version, data, 2); version = ntohs(version);
    std::memcpy(&length, data + 2, 2); length = ntohs(length);

    if (length > len) length = static_cast<uint16_t>(len);

    // IPFIX uses similar template structure as v9 but with different field numbering
    static thread_local std::unordered_map<uint16_t, std::vector<std::pair<uint16_t, uint16_t>>> templates;

    std::vector<NetFlowRecord> records;
    size_t offset = 16;

    while (offset + 4 <= length) {
        uint16_t set_id, set_len;
        std::memcpy(&set_id, data + offset, 2); set_id = ntohs(set_id);
        std::memcpy(&set_len, data + offset + 2, 2); set_len = ntohs(set_len);

        if (offset + set_len > length) break;

        if (set_id == 2) {
            // Template set
            size_t tpl_offset = offset + 4;
            while (tpl_offset + 4 <= offset + set_len) {
                uint16_t template_id, field_count;
                std::memcpy(&template_id, data + tpl_offset, 2); template_id = ntohs(template_id);
                std::memcpy(&field_count, data + tpl_offset + 2, 2); field_count = ntohs(field_count);
                tpl_offset += 4;

                std::vector<std::pair<uint16_t, uint16_t>> fields;
                for (uint16_t f = 0; f < field_count && tpl_offset + 4 <= offset + set_len; ++f) {
                    uint16_t field_type, field_len;
                    std::memcpy(&field_type, data + tpl_offset, 2); field_type = ntohs(field_type);
                    std::memcpy(&field_len, data + tpl_offset + 2, 2); field_len = ntohs(field_len);
                    fields.emplace_back(field_type, field_len);
                    tpl_offset += 4;
                }
                templates[template_id] = std::move(fields);
            }
        } else if (set_id >= 256) {
            // Data set
            auto tpl_it = templates.find(set_id);
            if (tpl_it != templates.end()) {
                const auto& fields = tpl_it->second;
                size_t record_offset = offset + 4;
                size_t record_size = 0;
                for (const auto& [type, flen] : fields) record_size += flen;

                while (record_offset + record_size <= offset + set_len) {
                    NetFlowRecord record;
                    record.version = NetFlowVersion::IPFIX;
                    size_t field_offset = record_offset;

                    for (const auto& [field_type, field_len] : fields) {
                        auto read_uint = [&](size_t flen) -> uint32_t {
                            uint32_t val = 0;
                            std::memcpy(&val, data + field_offset, flen);
                            switch (flen) {
                                case 1: return val & 0xFF;
                                case 2: return ntohs(val & 0xFFFF);
                                case 4: return ntohl(val);
                                default: return val;
                            }
                        };

                        // IPFIX field numbers are similar to NetFlow v9
                        switch (field_type) {
                            case 1: record.d_octets = read_uint(field_len); break;
                            case 2: record.d_pkts = read_uint(field_len); break;
                            case 4: record.protocol = data[field_offset]; break;
                            case 6: record.tcp_flags = data[field_offset]; break;
                            case 7: record.src_port = read_uint(field_len) & 0xFFFF; break;
                            case 8: std::memcpy(&record.src_addr, data + field_offset, 4); break;
                            case 10: record.dst_port = read_uint(field_len) & 0xFFFF; break;
                            case 11: std::memcpy(&record.dst_addr, data + field_offset, 4); break;
                            default: break;
                        }
                        field_offset += field_len;
                    }
                    records.push_back(record);
                    record_offset += record_size;
                }
            }
        }

        offset += set_len;
    }

    return records;
}

std::string NetFlowParser::ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string NetFlowParser::protocol_to_string(uint8_t proto) {
    switch (proto) {
        case 1:  return "icmp";
        case 6:  return "tcp";
        case 17: return "udp";
        case 47: return "gre";
        case 50: return "esp";
        case 51: return "ah";
        case 58: return "icmpv6";
        case 89: return "ospf";
        case 132: return "sctp";
        default: return "unknown";
    }
}

std::string NetFlowParser::tcp_flags_to_string(uint8_t flags) {
    std::string result;
    if (flags & 0x01) result += "FIN";
    if (flags & 0x02) result += (result.empty() ? "" : ",") + "SYN";
    if (flags & 0x04) result += (result.empty() ? "" : ",") + "RST";
    if (flags & 0x08) result += (result.empty() ? "" : ",") + "PSH";
    if (flags & 0x10) result += (result.empty() ? "" : ",") + "ACK";
    if (flags & 0x20) result += (result.empty() ? "" : ",") + "URG";
    if (flags & 0x40) result += (result.empty() ? "" : ",") + "ECE";
    if (flags & 0x80) result += (result.empty() ? "" : ",") + "CWR";
    return result;
}

} // namespace aiguard
