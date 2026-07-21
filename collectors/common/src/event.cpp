#include "aiguard/common/event.h"
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

namespace aiguard {

using json = nlohmann::json;

static std::atomic<EventId> global_event_id{1};

EventId Event::generate_id() {
    return global_event_id.fetch_add(1, std::memory_order_relaxed);
}

std::string Event::timestamp_to_iso8601(Timestamp ts) {
    auto secs = std::chrono::time_point_cast<std::chrono::seconds>(ts);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(ts - secs).count();

    std::time_t t = std::chrono::system_clock::to_time_t(secs);
    std::tm tm{};
    gmtime_r(&t, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms << 'Z';
    return oss.str();
}

Timestamp Event::parse_iso8601(std::string_view str) {
    // Parse ISO 8601 format: 2024-01-15T10:30:00.123Z
    std::tm tm{};
    int millis = 0;
    std::istringstream iss{std::string(str)};
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (iss.peek() == '.') {
        iss.ignore();
        iss >> millis;
    }
    std::time_t t = timegm(&tm);
    auto tp = std::chrono::system_clock::from_time_t(t);
    return tp + std::chrono::milliseconds(millis);
}

namespace {

json field_value_to_json(const FieldValue& fv) {
    return std::visit([](auto&& val) -> json {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return val;
        } else if constexpr (std::is_same_v<T, double>) {
            return val;
        } else if constexpr (std::is_same_v<T, bool>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<int64_t>>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<double>>) {
            return val;
        }
        return nullptr;
    }, fv);
}

FieldValue json_to_field_value(const json& j) {
    if (j.is_string()) return j.get<std::string>();
    if (j.is_number_integer()) return j.get<int64_t>();
    if (j.is_number_float()) return j.get<double>();
    if (j.is_boolean()) return j.get<bool>();
    if (j.is_array()) {
        if (!j.empty() && j[0].is_string()) {
            return j.get<std::vector<std::string>>();
        } else if (!j.empty() && j[0].is_number_integer()) {
            return j.get<std::vector<int64_t>>();
        } else if (!j.empty() && j[0].is_number_float()) {
            return j.get<std::vector<double>>();
        }
    }
    return j.is_string() ? FieldValue{j.get<std::string>()} : FieldValue{std::string{}};
}

} // anonymous namespace

std::string Event::to_json() const {
    json j;
    j["@timestamp"] = timestamp_to_iso8601(timestamp);
    j["event"]["id"] = id;
    j["event"]["category"] = category;
    j["event"]["type"] = type;
    j["event"]["action"] = action;
    j["event"]["outcome"] = outcome;
    j["event"]["severity"] = severity;
    j["event"]["severity_score"] = severity_score;
    j["event"]["dataset"] = dataset;
    j["event"]["module"] = module;

    j["source"]["ip"] = source_ip;
    j["source"]["port"] = source_port;
    j["source"]["host"]["name"] = source_host;

    j["destination"]["ip"] = destination_ip;
    j["destination"]["port"] = destination_port;

    j["network"]["transport"] = network_transport;
    j["network"]["protocol"] = network_protocol;
    j["network"]["bytes"] = network_bytes_in + network_bytes_out;
    j["network"]["packets"] = network_packets_in + network_packets_out;

    j["user"]["id"] = user_id;
    j["user"]["name"] = user_name;

    j["process"]["pid"] = process_pid;
    j["process"]["name"] = process_name;

    j["host"]["id"] = host_id;
    j["host"]["name"] = host_name;

    // Custom fields
    for (const auto& [key, val] : custom_fields) {
        j[key] = field_value_to_json(val);
    }

    // Raw data as base64
    if (!raw_data.empty()) {
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        for (size_t i = 0; i < raw_data.size(); i += 3) {
            uint32_t n = raw_data[i] << 16;
            if (i + 1 < raw_data.size()) n |= raw_data[i + 1] << 8;
            if (i + 2 < raw_data.size()) n |= raw_data[i + 2];
            encoded += b64[(n >> 18) & 0x3F];
            encoded += b64[(n >> 12) & 0x3F];
            encoded += (i + 1 < raw_data.size()) ? b64[(n >> 6) & 0x3F] : '=';
            encoded += (i + 2 < raw_data.size()) ? b64[n & 0x3F] : '=';
        }
        j["raw_data"] = encoded;
    }

    return j.dump();
}

std::unique_ptr<Event> Event::from_json(std::string_view json_str) {
    try {
        auto j = json::parse(json_str);
        auto event = std::make_unique<Event>();

        if (j.contains("@timestamp")) {
            event->timestamp = parse_iso8601(j["@timestamp"].get<std::string>());
        }
        if (j.contains("event")) {
            auto& e = j["event"];
            event->id = e.value("id", EventId{0});
            event->category = e.value("category", "");
            event->type = e.value("type", "");
            event->action = e.value("action", "");
            event->outcome = e.value("outcome", "");
            event->severity = e.value("severity", "info");
            event->severity_score = e.value("severity_score", uint8_t{0});
            event->dataset = e.value("dataset", "");
            event->module = e.value("module", "");
        }
        if (j.contains("source")) {
            auto& s = j["source"];
            event->source_ip = s.value("ip", "");
            event->source_port = s.value("port", uint16_t{0});
            if (s.contains("host")) event->source_host = s["host"].value("name", "");
        }
        if (j.contains("destination")) {
            auto& d = j["destination"];
            event->destination_ip = d.value("ip", "");
            event->destination_port = d.value("port", uint16_t{0});
        }
        if (j.contains("network")) {
            auto& n = j["network"];
            event->network_transport = n.value("transport", "");
            event->network_protocol = n.value("protocol", "");
        }
        if (j.contains("user")) {
            event->user_id = j["user"].value("id", "");
            event->user_name = j["user"].value("name", "");
        }
        if (j.contains("process")) {
            event->process_pid = j["process"].value("pid", "");
            event->process_name = j["process"].value("name", "");
        }
        if (j.contains("host")) {
            event->host_id = j["host"].value("id", "");
            event->host_name = j["host"].value("name", "");
        }

        // Extract custom fields
        for (auto it = j.begin(); it != j.end(); ++it) {
            const auto& key = it.key();
            if (key == "@timestamp" || key == "event" || key == "source" ||
                key == "destination" || key == "network" || key == "user" ||
                key == "process" || key == "host" || key == "raw_data") {
                continue;
            }
            event->custom_fields[key] = json_to_field_value(it.value());
        }

        return event;
    } catch (const std::exception& e) {
        return nullptr;
    }
}

} // namespace aiguard
