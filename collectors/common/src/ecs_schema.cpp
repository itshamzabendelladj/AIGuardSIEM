#include "aiguard/common/ecs_schema.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace aiguard {

ECSNormalizer::ECSNormalizer() {
    initialize_default_mappings();
}

void ECSNormalizer::initialize_default_mappings() {
    // Syslog mappings
    register_mapping("syslog", "host", ecs_fields::HOST_NAME);
    register_mapping("syslog", "program", ecs_fields::PROCESS_NAME);
    register_mapping("syslog", "facility", "log.syslog.facility.code");
    register_mapping("syslog", "severity", ecs_fields::EVENT_SEVERITY);
    register_mapping("syslog", "message", "message");

    // Windows Event Log mappings
    register_mapping("winlog", "ComputerName", ecs_fields::HOST_NAME);
    register_mapping("winlog", "EventID", "winlog.event_id");
    register_mapping("winlog", "Channel", "winlog.channel");
    register_mapping("winlog", "ProviderName", "winlog.provider_name");
    register_mapping("winlog", "TaskName", ecs_fields::EVENT_CATEGORY);

    // NetFlow mappings
    register_mapping("netflow", "srcaddr", ecs_fields::SOURCE_IP);
    register_mapping("netflow", "dstaddr", ecs_fields::DEST_IP);
    register_mapping("netflow", "srcport", ecs_fields::SOURCE_PORT,
        [](std::string_view v) -> FieldValue { return static_cast<int64_t>(std::stoul(std::string(v))); });
    register_mapping("netflow", "dstport", ecs_fields::DEST_PORT,
        [](std::string_view v) -> FieldValue { return static_cast<int64_t>(std::stoul(std::string(v))); });
    register_mapping("netflow", "prot", ecs_fields::NETWORK_TRANSPORT,
        [](std::string_view v) -> FieldValue {
            int proto = std::stoi(std::string(v));
            switch (proto) {
                case 6:  return FieldValue{std::string{"tcp"}};
                case 17: return FieldValue{std::string{"udp"}};
                case 1:  return FieldValue{std::string{"icmp"}};
                default: return FieldValue{std::string{"unknown"}};
            }
        });
    register_mapping("netflow", "dOctets", ecs_fields::NETWORK_BYTES,
        [](std::string_view v) -> FieldValue { return static_cast<int64_t>(std::stoul(std::string(v))); });
    register_mapping("netflow", "dPkts", ecs_fields::NETWORK_PACKETS,
        [](std::string_view v) -> FieldValue { return static_cast<int64_t>(std::stoul(std::string(v))); });

    // Zeek/DNS mappings
    register_mapping("zeek_dns", "query", "dns.question.name");
    register_mapping("zeek_dns", "rcode_name", "dns.response.code");
    register_mapping("zeek_dns", "qtype_name", "dns.question.type");

    // Zeek/HTTP mappings
    register_mapping("zeek_http", "uri", "url.path");
    register_mapping("zeek_http", "method", ecs_fields::EVENT_ACTION);
    register_mapping("zeek_http", "status_code", "http.response.status_code",
        [](std::string_view v) -> FieldValue { return static_cast<int64_t>(std::stoi(std::string(v))); });
    register_mapping("zeek_http", "user_agent", "user_agent.original");

    // Register valid ECS fields
    static const std::vector<std::string> valid_fields = {
        ecs_fields::EVENT_ID, ecs_fields::EVENT_KIND, ecs_fields::EVENT_CATEGORY,
        ecs_fields::EVENT_TYPE, ecs_fields::EVENT_ACTION, ecs_fields::EVENT_OUTCOME,
        ecs_fields::EVENT_SEVERITY, ecs_fields::EVENT_CREATED, ecs_fields::EVENT_MODULE,
        ecs_fields::EVENT_DATASET,
        ecs_fields::SOURCE_IP, ecs_fields::SOURCE_PORT, ecs_fields::SOURCE_HOST_NAME,
        ecs_fields::DEST_IP, ecs_fields::DEST_PORT, ecs_fields::DEST_HOST_NAME,
        ecs_fields::NETWORK_TRANSPORT, ecs_fields::NETWORK_PROTOCOL,
        ecs_fields::NETWORK_BYTES, ecs_fields::NETWORK_PACKETS,
        ecs_fields::USER_ID, ecs_fields::USER_NAME,
        ecs_fields::PROCESS_PID, ecs_fields::PROCESS_NAME, ecs_fields::PROCESS_CMD_LINE,
        ecs_fields::HOST_ID, ecs_fields::HOST_NAME, ecs_fields::HOST_OS_NAME,
        ecs_fields::TIMESTAMP,
        "message", "log.syslog.facility.code", "log.syslog.priority",
        "winlog.event_id", "winlog.channel", "winlog.provider_name",
        "dns.question.name", "dns.response.code", "dns.question.type",
        "url.path", "http.response.status_code", "user_agent.original",
        "url.full", "url.domain", "http.request.method",
    };

    for (const auto& f : valid_fields) {
        ecs_fields_[f] = true;
    }
}

void ECSNormalizer::register_mapping(const std::string& source_type,
                                      const std::string& source_field,
                                      const std::string& ecs_field,
                                      std::function<FieldValue(std::string_view)> transform) {
    mappings_[source_type].push_back({
        ecs_field, source_field, std::move(transform)
    });
    ecs_fields_[ecs_field] = true;
}

void ECSNormalizer::normalize(Event& event, const std::string& source_type) const {
    auto it = mappings_.find(source_type);
    if (it == mappings_.end()) {
        return;
    }

    for (const auto& mapping : it->second) {
        auto field_it = event.custom_fields.find(mapping.source_field);
        if (field_it == event.custom_fields.end()) {
            continue;
        }

        FieldValue value = field_it->second;
        if (mapping.transform) {
            // Extract string representation for transform
            std::string str_val;
            std::visit([&](auto&& v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, std::string>) {
                    str_val = v;
                } else if constexpr (std::is_same_v<T, int64_t>) {
                    str_val = std::to_string(v);
                } else if constexpr (std::is_same_v<T, double>) {
                    str_val = std::to_string(v);
                } else if constexpr (std::is_same_v<T, bool>) {
                    str_val = v ? "true" : "false";
                } else {
                    str_val = "";
                }
            }, value);
            value = mapping.transform(str_val);
        }

        // Set ECS field on event
        if (mapping.ecs_field == ecs_fields::SOURCE_IP) {
            if (std::holds_alternative<std::string>(value))
                event.source_ip = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::DEST_IP) {
            if (std::holds_alternative<std::string>(value))
                event.destination_ip = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::SOURCE_PORT) {
            if (std::holds_alternative<int64_t>(value))
                event.source_port = static_cast<uint16_t>(std::get<int64_t>(value));
        } else if (mapping.ecs_field == ecs_fields::DEST_PORT) {
            if (std::holds_alternative<int64_t>(value))
                event.destination_port = static_cast<uint16_t>(std::get<int64_t>(value));
        } else if (mapping.ecs_field == ecs_fields::HOST_NAME) {
            if (std::holds_alternative<std::string>(value))
                event.host_name = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::PROCESS_NAME) {
            if (std::holds_alternative<std::string>(value))
                event.process_name = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::EVENT_SEVERITY) {
            if (std::holds_alternative<std::string>(value))
                event.severity = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::EVENT_CATEGORY) {
            if (std::holds_alternative<std::string>(value))
                event.category = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::NETWORK_TRANSPORT) {
            if (std::holds_alternative<std::string>(value))
                event.network_transport = std::get<std::string>(value);
        } else if (mapping.ecs_field == ecs_fields::NETWORK_BYTES) {
            if (std::holds_alternative<int64_t>(value))
                event.network_bytes_in = std::get<int64_t>(value);
        } else if (mapping.ecs_field == ecs_fields::NETWORK_PACKETS) {
            if (std::holds_alternative<int64_t>(value))
                event.network_packets_in = std::get<int64_t>(value);
        } else {
            event.set_field(mapping.ecs_field, std::move(value));
        }
    }
}

std::vector<ECSFieldMapping> ECSNormalizer::get_mappings(const std::string& source_type) const {
    auto it = mappings_.find(source_type);
    if (it != mappings_.end()) return it->second;
    return {};
}

bool ECSNormalizer::is_ecs_field(std::string_view field) const {
    return ecs_fields_.count(std::string(field)) > 0;
}

std::vector<std::string> ECSNormalizer::get_source_types() const {
    std::vector<std::string> result;
    result.reserve(mappings_.size());
    for (const auto& [type, _] : mappings_) {
        result.push_back(type);
    }
    return result;
}

} // namespace aiguard
