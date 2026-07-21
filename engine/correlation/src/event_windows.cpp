#include "aiguard/engine/event_windows.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cmath>

namespace aiguard {

EventWindowManager::EventWindowManager() {
    windows_.reserve(10000);
}

void EventWindowManager::add_window(const WindowSpec& spec) {
    std::lock_guard<std::mutex> lock(mutex_);
    specs_.push_back(spec);
    spdlog::info("Window spec added: {} (type={}, size={}ms)",
                 spec.id, static_cast<int>(spec.type), spec.window_size_ms);
}

void EventWindowManager::set_result_callback(ResultCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}

std::string EventWindowManager::get_group_key(const Event& event, const std::string& field) const {
    if (field.empty()) return "_global_";

    if (field == "source.ip") return event.source_ip;
    if (field == "destination.ip") return event.destination_ip;
    if (field == "host.name") return event.host_name;
    if (field == "user.name") return event.user_name;
    if (field == "process.name") return event.process_name;
    if (field == "event.category") return event.category;

    auto val = event.get_field(field);
    if (val) {
        return std::visit([](auto&& v) -> std::string {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::string>) return v;
            else if constexpr (std::is_same_v<T, int64_t>) return std::to_string(v);
            else if constexpr (std::is_same_v<T, double>) return std::to_string(v);
            else if constexpr (std::is_same_v<T, bool>) return v ? "true" : "false";
            else return "";
        }, *val);
    }
    return "_unknown_";
}

double EventWindowManager::get_field_double(const Event& event, const std::string& field) const {
    if (field == "network.bytes") return static_cast<double>(event.network_bytes_in + event.network_bytes_out);
    if (field == "network.packets") return static_cast<double>(event.network_packets_in + event.network_packets_out);
    if (field == "source.port") return static_cast<double>(event.source_port);
    if (field == "destination.port") return static_cast<double>(event.destination_port);

    auto val = event.get_field(field);
    if (val) {
        return std::visit([](auto&& v) -> double {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, int64_t>) return static_cast<double>(v);
            else if constexpr (std::is_same_v<T, double>) return v;
            else if constexpr (std::is_same_v<T, bool>) return v ? 1.0 : 0.0;
            else {
                try { return std::stod(v); } catch (...) { return 0.0; }
            }
        }, *val);
    }
    return 0.0;
}

double EventWindowManager::aggregate(const std::vector<const Event*>& events,
                                      const std::string& function,
                                      const std::string& field) const {
    if (events.empty()) return 0.0;

    if (function == "count") return static_cast<double>(events.size());

    std::vector<double> values;
    values.reserve(events.size());
    for (const auto* e : events) {
        values.push_back(get_field_double(*e, field));
    }

    if (function == "sum") {
        double sum = 0;
        for (double v : values) sum += v;
        return sum;
    } else if (function == "avg") {
        double sum = 0;
        for (double v : values) sum += v;
        return sum / values.size();
    } else if (function == "min") {
        return *std::min_element(values.begin(), values.end());
    } else if (function == "max") {
        return *std::max_element(values.begin(), values.end());
    }

    return 0.0;
}

void EventWindowManager::process_tumbling(const WindowSpec& spec, const Event& event,
                                           const std::string& group_key) {
    auto& spec_windows = windows_[spec.id];
    auto& win = spec_windows[group_key];

    auto window_start = std::chrono::duration_cast<std::chrono::milliseconds>(
        event.timestamp.time_since_epoch()).count();
    window_start -= window_start % spec.window_size_ms;
    auto start_tp = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(window_start));

    if (win.events.empty() || win.start != start_tp) {
        // New window
        if (!win.events.empty()) {
            // Emit previous window
            std::vector<const Event*> ptrs;
            for (auto& e : win.events) ptrs.push_back(e.get());
            double val = aggregate(ptrs, spec.aggregation_function, spec.aggregation_field);

            WindowResult result;
            result.window_id = spec.id + "_" + group_key + "_" +
                std::to_string(window_start);
            result.spec_id = spec.id;
            result.window_start = win.start;
            result.window_end = win.end;
            result.group_key = group_key;
            result.aggregation_value = val;
            result.event_count = win.events.size();
            result.threshold_exceeded = val >= spec.threshold;
            if (callback_) callback_(result);
        }

        win.start = start_tp;
        win.end = start_tp + std::chrono::milliseconds(spec.window_size_ms);
        win.group_key = group_key;
    }

    win.events.push_back(std::make_unique<Event>(Event{
        .id = event.id,
        .timestamp = event.timestamp,
        .source_ip = event.source_ip,
        .destination_ip = event.destination_ip,
        .host_name = event.host_name,
        .user_name = event.user_name,
        .category = event.category,
        .action = event.action,
        .severity = event.severity
    }));
}

void EventWindowManager::process_sliding(const WindowSpec& spec, const Event& event,
                                          const std::string& group_key) {
    // Sliding window: each event creates a new window
    auto& spec_windows = windows_[spec.id];
    std::string window_key = group_key + "_" +
        std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            event.timestamp.time_since_epoch()).count());

    auto& win = spec_windows[window_key];
    win.start = event.timestamp;
    win.end = event.timestamp + std::chrono::milliseconds(spec.window_size_ms);
    win.group_key = group_key;

    win.events.push_back(std::make_unique<Event>(Event{
        .id = event.id,
        .timestamp = event.timestamp,
        .source_ip = event.source_ip,
        .destination_ip = event.destination_ip,
        .host_name = event.host_name,
        .user_name = event.user_name,
        .category = event.category,
        .action = event.action,
        .severity = event.severity
    }));
}

void EventWindowManager::process_session(const WindowSpec& spec, const Event& event,
                                          const std::string& group_key) {
    auto& spec_windows = windows_[spec.id];
    auto& win = spec_windows[group_key];

    if (win.events.empty()) {
        win.start = event.timestamp;
        win.end = event.timestamp;
        win.group_key = group_key;
    } else {
        auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
            event.timestamp - win.end);
        if (gap.count() > spec.gap_timeout_ms) {
            // Session expired - emit and start new
            std::vector<const Event*> ptrs;
            for (auto& e : win.events) ptrs.push_back(e.get());
            double val = aggregate(ptrs, spec.aggregation_function, spec.aggregation_field);

            WindowResult result;
            result.window_id = spec.id + "_" + group_key + "_session";
            result.spec_id = spec.id;
            result.window_start = win.start;
            result.window_end = win.end;
            result.group_key = group_key;
            result.aggregation_value = val;
            result.event_count = win.events.size();
            result.threshold_exceeded = val >= spec.threshold;
            if (callback_) callback_(result);

            win.events.clear();
            win.start = event.timestamp;
        }
        win.end = event.timestamp;
    }

    win.events.push_back(std::make_unique<Event>(Event{
        .id = event.id,
        .timestamp = event.timestamp,
        .source_ip = event.source_ip,
        .destination_ip = event.destination_ip,
        .host_name = event.host_name,
        .user_name = event.user_name,
        .category = event.category,
        .action = event.action,
        .severity = event.severity
    }));
}

void EventWindowManager::process_hopping(const WindowSpec& spec, const Event& event,
                                          const std::string& group_key) {
    // Hopping window: similar to tumbling but with hop interval
    auto event_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        event.timestamp.time_since_epoch()).count();

    // Calculate which windows this event belongs to
    int64_t first_window = (event_ms - spec.window_size_ms) / spec.slide_size_ms;
    int64_t last_window = event_ms / spec.slide_size_ms;

    auto& spec_windows = windows_[spec.id];

    for (int64_t w = first_window; w <= last_window; ++w) {
        auto window_start_ms = w * spec.slide_size_ms;
        auto window_end_ms = window_start_ms + spec.window_size_ms;

        if (event_ms < window_start_ms || event_ms >= window_end_ms) continue;

        std::string window_key = group_key + "_" + std::to_string(w);
        auto& win = spec_windows[window_key];

        if (win.events.empty()) {
            win.start = std::chrono::system_clock::time_point(
                std::chrono::milliseconds(window_start_ms));
            win.end = std::chrono::system_clock::time_point(
                std::chrono::milliseconds(window_end_ms));
            win.group_key = group_key;
        }

        win.events.push_back(std::make_unique<Event>(Event{
            .id = event.id,
            .timestamp = event.timestamp,
            .source_ip = event.source_ip,
            .destination_ip = event.destination_ip,
            .host_name = event.host_name,
            .user_name = event.user_name,
            .category = event.category,
            .action = event.action,
            .severity = event.severity
        }));
    }
}

void EventWindowManager::process_event(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& spec : specs_) {
        std::string group_key = get_group_key(event, spec.group_by_field);

        switch (spec.type) {
            case WindowType::Tumbling:
                process_tumbling(spec, event, group_key);
                break;
            case WindowType::Sliding:
                process_sliding(spec, event, group_key);
                break;
            case WindowType::Session:
                process_session(spec, event, group_key);
                break;
            case WindowType::Hopping:
                process_hopping(spec, event, group_key);
                break;
        }
    }
}

std::vector<WindowResult> EventWindowManager::expire_windows() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<WindowResult> results;
    auto now = std::chrono::system_clock::now();

    for (auto& [spec_id, spec_windows] : windows_) {
        // Find the spec
        const WindowSpec* spec = nullptr;
        for (const auto& s : specs_) {
            if (s.id == spec_id) { spec = &s; break; }
        }
        if (!spec) continue;

        for (auto it = spec_windows.begin(); it != spec_windows.end();) {
            if (it->second.end <= now) {
                std::vector<const Event*> ptrs;
                for (auto& e : it->second.events) ptrs.push_back(e.get());
                double val = aggregate(ptrs, spec->aggregation_function, spec->aggregation_field);

                WindowResult result;
                result.window_id = spec_id + "_" + it->second.group_key;
                result.spec_id = spec_id;
                result.window_start = it->second.start;
                result.window_end = it->second.end;
                result.group_key = it->second.group_key;
                result.aggregation_value = val;
                result.event_count = it->second.events.size();
                result.threshold_exceeded = val >= spec->threshold;

                results.push_back(result);
                it = spec_windows.erase(it);
            } else {
                ++it;
            }
        }
    }

    return results;
}

size_t EventWindowManager::active_window_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [_, spec_windows] : windows_) {
        count += spec_windows.size();
    }
    return count;
}

void EventWindowManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    windows_.clear();
}

} // namespace aiguard
