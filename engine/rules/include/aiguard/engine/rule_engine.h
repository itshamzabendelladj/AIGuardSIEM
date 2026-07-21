#pragma once

#include "aiguard/engine/correlation_engine.h"
#include "aiguard/engine/sigma_compiler.h"
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace aiguard {

/// Custom DSL rule
struct DSLRule {
    std::string id;
    std::string name;
    std::string expression;   // Custom DSL expression
    Severity severity{Severity::Medium};
    int64_t time_window_ms{60000};
    uint32_t threshold{1};
};

/// Rule performance profiling
struct RuleProfile {
    std::string rule_id;
    uint64_t match_count{0};
    uint64_t evaluation_count{0};
    double avg_evaluation_time_ns{0};
    double match_rate{0.0};
    std::chrono::system_clock::time_point last_match;
};

/// Unified rule engine - manages all detection rules
///
/// Features:
/// - Sigma rule compilation and management
/// - Custom DSL with JIT compilation
/// - YARA-L support
/// - Rule performance profiling
/// - Hot rule loading/reloading
class RuleEngine {
public:
    RuleEngine();
    ~RuleEngine() = default;

    /// Load Sigma rules from directory
    size_t load_sigma_rules(const std::string& dir_path);

    /// Add a single correlation rule
    void add_rule(std::unique_ptr<CorrelationRule> rule);

    /// Remove a rule
    bool remove_rule(const std::string& rule_id);

    /// Get all rules
    std::vector<const CorrelationRule*> get_rules() const;

    /// Get rule count
    [[nodiscard]] size_t rule_count() const;

    /// Get rule profiles
    std::vector<RuleProfile> get_profiles() const;

    /// Reload rules from Sigma directory
    size_t reload_sigma_rules(const std::string& dir_path);

    /// Get statistics
    struct Stats {
        uint64_t total_rules{0};
        uint64_t sigma_rules{0};
        uint64_t dsl_rules{0};
        uint64_t rules_loaded{0};
        uint64_t rules_failed{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    SigmaCompiler sigma_compiler_;
    std::unordered_map<std::string, std::unique_ptr<CorrelationRule>> rules_;
    std::unordered_map<std::string, RuleProfile> profiles_;
    mutable std::mutex mutex_;
    Stats stats_;
};

} // namespace aiguard
