#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <variant>
#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>
#include <optional>

namespace aiguard {

using Timestamp = std::chrono::system_clock::time_point;
using EventId = uint64_t;

/// Field value type - supports multiple data types for ECS events
using FieldValue = std::variant<
    std::string,
    int64_t,
    double,
    bool,
    std::vector<std::string>,
    std::vector<int64_t>,
    std::vector<double>
>;

/// ECS (Elastic Common Schema) compliant event
///
/// All ingested data is normalized to this structure following
/// the Elastic Common Schema specification for interoperability.
struct Event {
    EventId id{0};
    Timestamp timestamp{};
    std::string source_type;
    std::string source_host;
    std::string source_ip;
    uint16_t source_port{0};
    std::string destination_ip;
    uint16_t destination_port{0};
    std::string protocol;
    std::string action;
    std::string outcome;
    std::string severity;        // info, low, medium, high, critical
    uint8_t severity_score{0};   // 0-100
    std::string category;        // ECS event category
    std::string type;            // ECS event type
    std::string dataset;
    std::string module;
    std::string user_name;
    std::string user_id;
    std::string process_name;
    std::string process_pid;
    std::string host_name;
    std::string host_id;
    std::string network_transport;
    std::string network_protocol;
    int64_t network_bytes_in{0};
    int64_t network_bytes_out{0};
    int64_t network_packets_in{0};
    int64_t network_packets_out{0};
    std::vector<uint8_t> raw_data;
    std::map<std::string, FieldValue> custom_fields;
    std::atomic<int> ref_count{1};

    Event() = default;
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
    Event(Event&&) = default;
    Event& operator=(Event&&) = default;

    /// Set a custom field
    void set_field(const std::string& key, FieldValue value) {
        custom_fields[key] = std::move(value);
    }

    /// Get a custom field
    [[nodiscard]] std::optional<FieldValue> get_field(const std::string& key) const {
        auto it = custom_fields.find(key);
        if (it != custom_fields.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /// Serialize to JSON string
    [[nodiscard]] std::string to_json() const;

    /// Deserialize from JSON string
    static std::unique_ptr<Event> from_json(std::string_view json);

    /// Generate unique event ID
    static EventId generate_id();

    /// Get current timestamp
    static Timestamp now() {
        return std::chrono::system_clock::now();
    }

    /// Convert timestamp to ISO 8601 string
    static std::string timestamp_to_iso8601(Timestamp ts);

    /// Parse ISO 8601 string to timestamp
    static Timestamp parse_iso8601(std::string_view str);
};

/// Event batch for bulk processing
struct EventBatch {
    std::vector<std::unique_ptr<Event>> events;
    size_t total_bytes{0};

    void add(std::unique_ptr<Event> event) {
        total_bytes += event->raw_data.size();
        events.push_back(std::move(event));
    }

    [[nodiscard]] size_t size() const { return events.size(); }
    [[nodiscard]] bool empty() const { return events.empty(); }
    void clear() { events.clear(); total_bytes = 0; }
};

/// Severity levels
enum class Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/// Convert severity enum to string
inline std::string_view severity_to_string(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
        default:                 return "unknown";
    }
}

/// Parse severity from string
inline Severity string_to_severity(std::string_view s) {
    if (s == "info" || s == "informational") return Severity::Info;
    if (s == "low")      return Severity::Low;
    if (s == "medium")   return Severity::Medium;
    if (s == "high")     return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

} // namespace aiguard
