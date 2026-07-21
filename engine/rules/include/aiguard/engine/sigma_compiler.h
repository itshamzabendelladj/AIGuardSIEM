#pragma once

#include "aiguard/engine/correlation_engine.h"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>

namespace aiguard {

/// Sigma rule detection field
struct SigmaDetection {
    std::string field;
    std::vector<std::string> values;
    std::vector<std::string> modifiers;  // contains, startswith, endswith, regex, etc.
    std::string operator_type{"eq"};    // eq, ne, contains, startswith, etc.
};

/// Sigma rule log source
struct SigmaLogSource {
    std::string product;
    std::string category;
    std::string service;
    std::string definition;
};

/// Parsed Sigma rule
struct SigmaRule {
    std::string id;
    std::string title;
    std::string status;            // experimental, test, stable
    std::string description;
    std::string author;
    std::string license;
    std::vector<std::string> tags; // MITRE ATT&CK tags
    std::vector<std::string> references;
    std::string level;             // informational, low, medium, high, critical
    SigmaLogSource logsource;
    std::vector<SigmaDetection> detection;
    std::string condition;         // Sigma condition expression
    std::string falsepositives;
};

/// Sigma rule compiler - converts Sigma YAML to CorrelationRule
///
/// Supports:
/// - Sigma rule parsing from YAML
/// - Condition expression compilation (AND, OR, NOT, selection keywords)
/// - Field modifier support (contains, startswith, endswith, regex)
/// - MITRE ATT&CK tag extraction
/// - Bulk rule loading from directory
class SigmaCompiler {
public:
    SigmaCompiler();

    /// Compile a Sigma rule from YAML
    std::unique_ptr<CorrelationRule> compile(const std::string& yaml);

    /// Compile all Sigma rules from a directory
    std::vector<std::unique_ptr<CorrelationRule>> compile_directory(const std::string& dir_path);

    /// Get compilation statistics
    struct Stats {
        uint64_t rules_compiled{0};
        uint64_t rules_failed{0};
        uint64_t conditions_parsed{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    /// Parse YAML (simplified parser)
    std::unordered_map<std::string, std::string> parse_yaml_simple(const std::string& yaml);

    /// Parse detection section
    std::vector<SigmaDetection> parse_detection(const std::string& detection_yaml);

    /// Compile condition expression
    std::vector<Condition> compile_condition(const std::string& condition,
                                              const std::vector<SigmaDetection>& detections);

    /// Extract MITRE tags
    std::pair<std::string, std::string> extract_mitre(const std::vector<std::string>& tags);

    /// Map Sigma level to severity
    Severity map_level(const std::string& level);

    Stats stats_;
};

} // namespace aiguard
