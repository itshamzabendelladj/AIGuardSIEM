#include "aiguard/engine/correlation_engine.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cmath>
#include <regex>
#include <cstring>

#ifdef AIGUARD_AVX512
#include <immintrin.h>
#endif

namespace aiguard {

CorrelationEngine::CorrelationEngine() {
    rules_.reserve(1000);
}

void CorrelationEngine::add_rule(std::unique_ptr<CorrelationRule> rule) {
    // Pre-compile regexes
    for (auto& cond : rule->conditions) {
        if (cond.op == "regex" && !cond.value.empty()) {
            try {
                cond.compiled_regex = std::make_shared<std::regex>(cond.value);
            } catch (const std::regex_error& e) {
                spdlog::error("Invalid regex in rule {} condition {}: {}", rule->id, cond.field, e.what());
            }
        }
    }

    std::lock_guard<std::shared_mutex> lock(rules_mutex_);
    std::string id = rule->id;
    rules_[id] = std::move(rule);
    spdlog::info("Correlation rule added: {} ({})", id, rules_[id]->name);
}

bool CorrelationEngine::remove_rule(const std::string& rule_id) {
    std::lock_guard<std::shared_mutex> lock(rules_mutex_);
    auto it = rules_.find(rule_id);
    if (it == rules_.end()) return false;
    rules_.erase(it);
    spdlog::info("Correlation rule removed: {}", rule_id);
    return true;
}

std::string CorrelationEngine::get_field_string(const Event& event, const std::string& field) const {
    // Check standard fields
    if (field == "source.ip" || field == "source_ip") return event.source_ip;
    if (field == "destination.ip" || field == "destination_ip") return event.destination_ip;
    if (field == "host.name" || field == "host_name") return event.host_name;
    if (field == "user.name" || field == "user_name") return event.user_name;
    if (field == "process.name" || field == "process_name") return event.process_name;
    if (field == "event.action" || field == "action") return event.action;
    if (field == "event.category" || field == "category") return event.category;
    if (field == "event.type" || field == "type") return event.type;
    if (field == "event.severity" || field == "severity") return event.severity;
    if (field == "source.port" || field == "source_port") return std::to_string(event.source_port);
    if (field == "destination.port" || field == "destination_port") return std::to_string(event.destination_port);
    if (field == "network.transport" || field == "network_transport") return event.network_transport;
    if (field == "network.protocol" || field == "network_protocol") return event.network_protocol;
    if (field == "process.pid" || field == "process_pid") return event.process_pid;

    // Check custom fields
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

    return "";
}

bool CorrelationEngine::check_condition(const Event& event, const Condition& cond) const {
    std::string field_value = get_field_string(event, cond.field);
    if (field_value.empty() && cond.op != "exists") return false;

    if (cond.op == "=" || cond.op == "==") {
        return field_value == cond.value;
    } else if (cond.op == "!=") {
        return field_value != cond.value;
    } else if (cond.op == "contains") {
        return field_value.find(cond.value) != std::string::npos;
    } else if (cond.op == "startswith") {
        return field_value.starts_with(cond.value);
    } else if (cond.op == "endswith") {
        return field_value.ends_with(cond.value);
    } else if (cond.op == "regex") {
        if (cond.compiled_regex) {
            try {
                return std::regex_search(field_value, *cond.compiled_regex);
            } catch (...) {
                return false;
            }
        }
        return false;
    } else if (cond.op == "exists") {
        return !field_value.empty();
    } else if (cond.op == ">") {
        try {
            return std::stod(field_value) > std::stod(cond.value);
        } catch (...) { return false; }
    } else if (cond.op == "<") {
        try {
            return std::stod(field_value) < std::stod(cond.value);
        } catch (...) { return false; }
    } else if (cond.op == ">=") {
        try {
            return std::stod(field_value) >= std::stod(cond.value);
        } catch (...) { return false; }
    } else if (cond.op == "<=") {
        try {
            return std::stod(field_value) <= std::stod(cond.value);
        } catch (...) { return false; }
    } else if (cond.op == "in") {
        // Comma-separated list
        std::stringstream ss(cond.value);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (field_value == item) return true;
        }
        return false;
    }

    return false;
}

bool CorrelationEngine::matches_conditions(const Event& event, const CorrelationRule& rule) const {
    for (const auto& cond : rule.conditions) {
        if (!check_condition(event, cond)) {
            return false;
        }
    }
    return true;
}

bool CorrelationEngine::simd_string_compare(const std::string& a, const std::string& b,
                                             const std::string& op) const {
#ifdef AIGUARD_AVX512
    if (op == "=" && a.size() == b.size()) {
        size_t len = a.size();
        size_t i = 0;
        // Process 64 bytes at a time with AVX-512
        while (i + 64 <= len) {
            __m512i va = _mm512_loadu_si512(a.data() + i);
            __m512i vb = _mm512_loadu_si512(b.data() + i);
            __mmask64 mask = _mm512_cmpeq_epi8_mask(va, vb);
            if (mask != 0xFFFFFFFFFFFFFFFFULL) return false;
            i += 64;
        }
        // Handle remaining bytes
        return std::memcmp(a.data() + i, b.data() + i, len - i) == 0;
    }
#endif
    // Fallback to standard comparison
    if (op == "=") return a == b;
    return false;
}

std::vector<Alert> CorrelationEngine::process_event(const Event& event) {
    std::vector<Alert> alerts;

    std::shared_lock<std::shared_mutex> rules_lock(rules_mutex_);
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.events_processed++;
        stats_.rules_evaluated += rules_.size();
    }

    for (const auto& [rule_id, rule] : rules_) {
        if (!matches_conditions(event, *rule)) continue;

        // Determine aggregation key
        std::string agg_key;
        if (!rule->aggregation_field.empty()) {
            agg_key = get_field_string(event, rule->aggregation_field);
        }
        if (agg_key.empty()) agg_key = "_global_";

        // Update correlation state
        std::lock_guard<std::mutex> state_lock(state_mutex_);
        auto& rule_state = state_[rule_id];
        auto& key_state = rule_state[agg_key];

        if (key_state.timestamps.empty()) {
            key_state.first_seen = event.timestamp;
        }
        key_state.last_seen = event.timestamp;
        key_state.timestamps.push_back(event.timestamp);

        // Keep only events within the time window
        auto window_start = event.timestamp - std::chrono::milliseconds(rule->time_window_ms);
        while (!key_state.timestamps.empty() &&
               key_state.timestamps.front() < window_start) {
            key_state.timestamps.erase(key_state.timestamps.begin());
        }

        // Store triggering event (limit stored events)
        if (key_state.events.size() < 100) {
            Event copy;
            copy.id = event.id;
            copy.timestamp = event.timestamp;
            copy.source_ip = event.source_ip;
            copy.destination_ip = event.destination_ip;
            copy.host_name = event.host_name;
            copy.user_name = event.user_name;
            copy.process_name = event.process_name;
            copy.category = event.category;
            copy.action = event.action;
            copy.severity = event.severity;
            key_state.events.push_back(std::move(copy));
        }

        // Check threshold
        if (key_state.timestamps.size() >= rule->threshold) {
            Alert alert;
            alert.id = "alert-" + std::to_string(stats_.alerts_generated + 1);
            alert.rule_id = rule_id;
            alert.rule_name = rule->name;
            alert.description = rule->description;
            alert.mitre_tactic = rule->mitre_tactic;
            alert.mitre_technique = rule->mitre_technique;
            alert.severity = rule->severity;
            alert.severity_score = rule->severity_score;
            alert.timestamp = event.timestamp;
            alert.triggering_events = key_state.events;
            alert.aggregation_key = agg_key;
            alert.match_count = static_cast<uint32_t>(key_state.timestamps.size());
            alert.action = rule->action;

            alerts.push_back(alert);

            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.alerts_generated++;
                stats_.rules_matched++;
            }

            // Reset state after alert
            key_state.timestamps.clear();
            key_state.events.clear();
        }
    }

    return alerts;
}

std::vector<Alert> CorrelationEngine::process_events(const std::vector<std::unique_ptr<Event>>& events) {
    std::vector<Alert> all_alerts;
    for (const auto& event : events) {
        auto alerts = process_event(*event);
        all_alerts.insert(all_alerts.end(), alerts.begin(), alerts.end());
    }
    return all_alerts;
}

std::vector<const CorrelationRule*> CorrelationEngine::get_rules() const {
    std::shared_lock<std::shared_mutex> lock(rules_mutex_);
    std::vector<const CorrelationRule*> result;
    result.reserve(rules_.size());
    for (const auto& [_, rule] : rules_) {
        result.push_back(rule.get());
    }
    return result;
}

size_t CorrelationEngine::rule_count() const {
    std::shared_lock<std::shared_mutex> lock(rules_mutex_);
    return rules_.size();
}

void CorrelationEngine::cleanup_expired() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto now = std::chrono::system_clock::now();
    for (auto& [rule_id, rule_state] : state_) {
        // Get timeout for this rule
        int64_t timeout_ms = 60000;  // Default 60s
        {
            std::shared_lock<std::shared_mutex> rules_lock(rules_mutex_);
            auto it = rules_.find(rule_id);
            if (it != rules_.end()) {
                timeout_ms = it->second->time_window_ms;
            }
        }
        auto cutoff = now - std::chrono::milliseconds(timeout_ms);

        for (auto it = rule_state.begin(); it != rule_state.end();) {
            if (it->second.last_seen < cutoff) {
                it = rule_state.erase(it);
            } else {
                ++it;
            }
        }
    }
}

CorrelationEngine::Stats CorrelationEngine::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
