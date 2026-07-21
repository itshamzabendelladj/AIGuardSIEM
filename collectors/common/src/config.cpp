#include "aiguard/common/config.h"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <regex>

namespace aiguard {

using json = nlohmann::json;

Config::Config(std::string_view config_file)
    : config_file_(config_file) {
    load(config_file_);
}

bool Config::load(std::string_view file_path) {
    std::ifstream file(std::string(file_path));
    if (!file.is_open()) {
        spdlog::warn("Config file not found: {}", file_path);
        return false;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    if (file_path.ends_with(".json")) {
        parse_json(content);
    } else {
        parse_yaml(content);
    }

    substitute_env_vars();
    spdlog::info("Config loaded from: {}", file_path);
    return true;
}

bool Config::reload() {
    if (config_file_.empty()) return false;
    return load(config_file_);
}

bool Config::save(std::string_view file_path) const {
    std::ofstream file(std::string(file_path));
    if (!file.is_open()) return false;
    if (file_path.ends_with(".json")) {
        file << to_json();
    } else {
        file << to_yaml();
    }
    return true;
}

std::optional<std::string> Config::get_string(std::string_view key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = values_.find(std::string(key));
    if (it != values_.end()) return it->second;
    return std::nullopt;
}

std::optional<int64_t> Config::get_int(std::string_view key) const {
    auto val = get_string(key);
    if (!val) return std::nullopt;
    try {
        return std::stoll(*val);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<double> Config::get_double(std::string_view key) const {
    auto val = get_string(key);
    if (!val) return std::nullopt;
    try {
        return std::stod(*val);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<bool> Config::get_bool(std::string_view key) const {
    auto val = get_string(key);
    if (!val) return std::nullopt;
    std::string lower = *val;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower == "true" || lower == "yes" || lower == "1" || lower == "on";
}

std::optional<std::vector<std::string>> Config::get_string_list(std::string_view key) const {
    auto val = get_string(key);
    if (!val) return std::nullopt;
    std::vector<std::string> result;
    std::stringstream ss(*val);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) result.push_back(item);
    }
    return result;
}

void Config::set(std::string_view key, std::string_view value) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        values_[std::string(key)] = std::string(value);
    }
    for (const auto& cb : change_callbacks_) {
        cb(std::string(key), std::string(value));
    }
}

void Config::set(std::string_view key, int64_t value) {
    set(key, std::to_string(value));
}

void Config::set(std::string_view key, double value) {
    set(key, std::to_string(value));
}

void Config::set(std::string_view key, bool value) {
    set(key, value ? "true" : "false");
}

bool Config::has(std::string_view key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return values_.count(std::string(key)) > 0;
}

std::vector<std::string> Config::get_keys_with_prefix(std::string_view prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [key, _] : values_) {
        if (key.starts_with(prefix)) {
            result.push_back(key);
        }
    }
    return result;
}

void Config::on_change(ChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    change_callbacks_.push_back(std::move(callback));
}

void Config::parse_yaml(std::string_view content) {
    std::istringstream stream{std::string(content)};
    std::string line;
    std::vector<std::string> path_stack;
    int last_indent = -1;

    while (std::getline(stream, line)) {
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        if (line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }

        size_t indent = line.find_first_not_of(" \t");
        std::string trimmed = line.substr(indent);

        while (!path_stack.empty() && static_cast<int>(indent) <= last_indent) {
            path_stack.pop_back();
            last_indent -= 2;
        }

        size_t colon_pos = trimmed.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string key = trimmed.substr(0, colon_pos);
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);

        std::string value = trimmed.substr(colon_pos + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        } else if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'') {
            value = value.substr(1, value.size() - 2);
        }

        if (value.empty()) {
            path_stack.push_back(key);
            last_indent = static_cast<int>(indent);
        } else {
            std::string full_key;
            for (const auto& p : path_stack) {
                full_key += p + ".";
            }
            full_key += key;
            values_[full_key] = value;
        }
    }
}

void Config::parse_json(std::string_view content) {
    auto j = json::parse(content);
    std::function<void(const json&, const std::string&)> flatten;
    flatten = [&](const json& obj, const std::string& prefix) {
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
            if (it.value().is_object()) {
                flatten(it.value(), key);
            } else if (it.value().is_string()) {
                values_[key] = it.value().get<std::string>();
            } else if (it.value().is_number_integer()) {
                values_[key] = std::to_string(it.value().get<int64_t>());
            } else if (it.value().is_number_float()) {
                values_[key] = std::to_string(it.value().get<double>());
            } else if (it.value().is_boolean()) {
                values_[key] = it.value().get<bool>() ? "true" : "false";
            }
        }
    };
    flatten(j, "");
}

std::string Config::to_yaml() const {
    std::ostringstream oss;
    for (const auto& [key, value] : values_) {
        oss << key << ": " << value << "\n";
    }
    return oss.str();
}

std::string Config::to_json() const {
    json j;
    for (const auto& [key, value] : values_) {
        if (value == "true" || value == "false") {
            j[key] = (value == "true");
        } else {
            try {
                j[key] = std::stoll(value);
            } catch (...) {
                try {
                    j[key] = std::stod(value);
                } catch (...) {
                    j[key] = value;
                }
            }
        }
    }
    return j.dump(2);
}

void Config::substitute_env_vars() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::regex env_regex{R"(\$\{([^}]+)\})"};
    for (auto& [key, value] : values_) {
        std::string result = value;
        std::smatch match;
        while (std::regex_search(result, match, env_regex)) {
            const char* env_val = std::getenv(match[1].str().c_str());
            std::string replacement = env_val ? env_val : "";
            result = result.replace(match.position(), match.length(), replacement);
        }
        value = result;
    }
}

} // namespace aiguard
