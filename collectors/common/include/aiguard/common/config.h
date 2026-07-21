#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <optional>
#include <mutex>
#include <fstream>

namespace aiguard {

/// Configuration manager with hot-reload support
///
/// Supports YAML and JSON configuration files with
/// environment variable substitution and live updates.
class Config {
public:
    Config() = default;
    explicit Config(std::string_view config_file);

    /// Load configuration from file
    bool load(std::string_view file_path);

    /// Reload configuration from the same file
    bool reload();

    /// Save configuration to file
    bool save(std::string_view file_path) const;

    /// Get a string value
    [[nodiscard]] std::optional<std::string> get_string(std::string_view key) const;

    /// Get an integer value
    [[nodiscard]] std::optional<int64_t> get_int(std::string_view key) const;

    /// Get a double value
    [[nodiscard]] std::optional<double> get_double(std::string_view key) const;

    /// Get a boolean value
    [[nodiscard]] std::optional<bool> get_bool(std::string_view key) const;

    /// Get a string list value
    [[nodiscard]] std::optional<std::vector<std::string>> get_string_list(std::string_view key) const;

    /// Set a string value
    void set(std::string_view key, std::string_view value);

    /// Set an integer value
    void set(std::string_view key, int64_t value);

    /// Set a double value
    void set(std::string_view key, double value);

    /// Set a boolean value
    void set(std::string_view key, bool value);

    /// Check if key exists
    [[nodiscard]] bool has(std::string_view key) const;

    /// Get all keys with a given prefix
    [[nodiscard]] std::vector<std::string> get_keys_with_prefix(std::string_view prefix) const;

    /// Register a change callback
    using ChangeCallback = std::function<void(const std::string& key, const std::string& value)>;
    void on_change(ChangeCallback callback);

private:
    void parse_yaml(std::string_view content);
    void parse_json(std::string_view content);
    [[nodiscard]] std::string to_yaml() const;
    [[nodiscard]] std::string to_json() const;
    void substitute_env_vars();

    std::string config_file_;
    std::unordered_map<std::string, std::string> values_;
    std::vector<ChangeCallback> change_callbacks_;
    mutable std::mutex mutex_;
};

} // namespace aiguard
