#include "aiguard/engine/sigma_compiler.h"
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <filesystem>

namespace aiguard {

SigmaCompiler::SigmaCompiler() {
    stats_ = {};
}

std::unordered_map<std::string, std::string> SigmaCompiler::parse_yaml_simple(const std::string& yaml) {
    std::unordered_map<std::string, std::string> result;
    std::istringstream stream(yaml);
    std::string line;
    std::string current_key;
    std::string current_value;
    bool in_detection = false;
    int detection_indent = 0;

    while (std::getline(stream, line)) {
        // Skip comments and empty lines
        size_t comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;

        size_t indent = line.find_first_not_of(" \t");
        std::string trimmed = line.substr(indent);

        size_t colon = trimmed.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trimmed.substr(0, colon);
        std::string value = trimmed.substr(colon + 1);
        // Trim
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        // Remove quotes
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        if (!value.empty()) {
            result[key] = value;
        }
    }

    return result;
}

std::vector<SigmaDetection> SigmaCompiler::parse_detection(const std::string& detection_yaml) {
    std::vector<SigmaDetection> detections;
    std::istringstream stream(detection_yaml);
    std::string line;
    std::string current_selection;
    SigmaDetection current_det;
    bool in_selection = false;

    while (std::getline(stream, line)) {
        size_t indent = line.find_first_not_of(" \t");
        if (indent == std::string::npos) continue;
        std::string trimmed = line.substr(indent);

        // Check if this is a selection name (top-level key)
        if (indent <= 4 && trimmed.find(':') != std::string::npos) {
            size_t colon = trimmed.find(':');
            std::string name = trimmed.substr(0, colon);
            std::string rest = trimmed.substr(colon + 1);
            rest.erase(0, rest.find_first_not_of(" \t"));

            if (name == "condition") {
                // Handled separately
                continue;
            }

            current_selection = name;
            in_selection = true;

            if (!rest.empty()) {
                // Inline value
                SigmaDetection det;
                det.field = current_selection;
                det.values.push_back(rest);
                detections.push_back(det);
            }
        } else if (in_selection && trimmed.find(':') != std::string::npos) {
            size_t colon = trimmed.find(':');
            std::string field = trimmed.substr(0, colon);
            std::string value = trimmed.substr(colon + 1);
            field.erase(0, field.find_first_not_of(" \t"));
            field.erase(field.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            // Remove quotes
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }

            // Check for modifiers (pipe-separated)
            std::vector<std::string> parts;
            std::stringstream ss(value);
            std::string part;
            while (std::getline(ss, part, '|')) {
                part.erase(0, part.find_first_not_of(" \t"));
                part.erase(part.find_last_not_of(" \t") + 1);
                parts.push_back(part);
            }

            SigmaDetection det;
            det.field = field;
            if (parts.size() > 1) {
                det.values.push_back(parts[0]);
                for (size_t i = 1; i < parts.size(); ++i) {
                    det.modifiers.push_back(parts[i]);
                }
                det.operator_type = det.modifiers[0];
            } else {
                det.values.push_back(value);
                det.operator_type = "eq";
            }
            detections.push_back(det);
        }
    }

    return detections;
}

std::vector<Condition> SigmaCompiler::compile_condition(const std::string& condition,
                                                          const std::vector<SigmaDetection>& detections) {
    std::vector<Condition> conditions;

    // Simple condition parser: handle "selection1 AND selection2", "selection1 OR selection2"
    // For now, combine all detections with AND logic
    for (const auto& det : detections) {
        Condition cond;
        cond.field = det.field;

        if (det.operator_type == "contains") {
            cond.op = "contains";
        } else if (det.operator_type == "startswith") {
            cond.op = "startswith";
        } else if (det.operator_type == "endswith") {
            cond.op = "endswith";
        } else if (det.operator_type == "regex") {
            cond.op = "regex";
        } else {
            cond.op = "=";
        }

        if (!det.values.empty()) {
            cond.value = det.values[0];
        }

        conditions.push_back(cond);
    }

    return conditions;
}

std::pair<std::string, std::string> SigmaCompiler::extract_mitre(const std::vector<std::string>& tags) {
    std::string tactic, technique;
    for (const auto& tag : tags) {
        if (tag.find("attack.t") != std::string::npos) {
            // Extract technique ID
            auto pos = tag.find("attack.t");
            technique = tag.substr(pos + 7);
            // Remove trailing parts after .
            auto dot = technique.find('.');
            if (dot != std::string::npos) technique = technique.substr(0, dot);
        } else if (tag.find("attack.") != std::string::npos) {
            auto pos = tag.find("attack.");
            std::string rest = tag.substr(pos + 7);
            // Tactic names
            tactic = rest;
        }
    }
    return {tactic, technique};
}

Severity SigmaCompiler::map_level(const std::string& level) {
    if (level == "critical") return Severity::Critical;
    if (level == "high")     return Severity::High;
    if (level == "medium")   return Severity::Medium;
    if (level == "low")      return Severity::Low;
    return Severity::Info;
}

std::unique_ptr<CorrelationRule> SigmaCompiler::compile(const std::string& yaml) {
    try {
        // Parse YAML (simplified - production would use yaml-cpp)
        auto kv = parse_yaml_simple(yaml);

        auto rule = std::make_unique<CorrelationRule>();

        rule->id = kv.count("id") ? kv["id"] : "rule-" + std::to_string(stats_.rules_compiled + 1);
        rule->name = kv.count("title") ? kv["title"] : "Untitled Rule";
        rule->description = kv.count("description") ? kv["description"] : "";
        rule->action = "alert";

        // Map level
        std::string level = kv.count("level") ? kv["level"] : "medium";
        rule->severity = map_level(level);
        rule->severity_score = static_cast<uint8_t>(static_cast<int>(rule->severity) * 20);

        // Extract tags
        std::vector<std::string> tags;
        if (kv.count("tags")) {
            std::stringstream ss(kv["tags"]);
            std::string tag;
            while (std::getline(ss, tag, ',')) {
                tag.erase(0, tag.find_first_not_of(" \t"));
                tag.erase(tag.find_last_not_of(" \t") + 1);
                tags.push_back(tag);
            }
        }

        auto [tactic, technique] = extract_mitre(tags);
        rule->mitre_tactic = tactic;
        rule->mitre_technique = technique;

        // Parse detection section
        // Extract detection block from YAML
        std::string detection_block;
        std::istringstream stream(yaml);
        std::string line;
        bool in_detection = false;
        while (std::getline(stream, line)) {
            if (line.find("detection:") != std::string::npos &&
                line.find_first_not_of(" \t") < 4) {
                in_detection = true;
                continue;
            }
            if (in_detection) {
                if (line.find_first_not_of(" \t") == std::string::npos) continue;
                if (line.find_first_not_of(" \t") < 4) break;  // Out of detection
                detection_block += line + "\n";
            }
        }

        auto detections = parse_detection(detection_block);

        // Extract condition
        std::string condition = "selection";
        for (const auto& [key, value] : kv) {
            if (key == "condition") condition = value;
        }

        rule->conditions = compile_condition(condition, detections);
        rule->threshold = 1;
        rule->time_window_ms = 60000;

        stats_.rules_compiled++;
        stats_.conditions_parsed++;

        spdlog::info("Compiled Sigma rule: {} ({})", rule->id, rule->name);
        return rule;

    } catch (const std::exception& e) {
        spdlog::error("Failed to compile Sigma rule: {}", e.what());
        stats_.rules_failed++;
        return nullptr;
    }
}

std::vector<std::unique_ptr<CorrelationRule>> SigmaCompiler::compile_directory(const std::string& dir_path) {
    std::vector<std::unique_ptr<CorrelationRule>> rules;

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir_path)) {
            if (entry.path().extension() == ".yml" || entry.path().extension() == ".yaml") {
                std::ifstream file(entry.path());
                if (!file.is_open()) continue;
                std::stringstream ss;
                ss << file.rdbuf();
                auto rule = compile(ss.str());
                if (rule) {
                    rules.push_back(std::move(rule));
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to read Sigma rules directory: {}", e.what());
    }

    spdlog::info("Compiled {} Sigma rules from {}", rules.size(), dir_path);
    return rules;
}

SigmaCompiler::Stats SigmaCompiler::get_stats() const {
    return stats_;
}

} // namespace aiguard
