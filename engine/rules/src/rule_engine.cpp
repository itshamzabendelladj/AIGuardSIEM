#include "aiguard/engine/rule_engine.h"
#include <spdlog/spdlog.h>

namespace aiguard {

RuleEngine::RuleEngine() {
    stats_ = {};
}

size_t RuleEngine::load_sigma_rules(const std::string& dir_path) {
    auto rules = sigma_compiler_.compile_directory(dir_path);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& rule : rules) {
        std::string id = rule->id;
        rules_[id] = std::move(rule);
        profiles_[id] = RuleProfile{.rule_id = id};
        stats_.sigma_rules++;
        stats_.total_rules++;
        stats_.rules_loaded++;
    }
    spdlog::info("Rule engine loaded {} Sigma rules (total: {})", rules.size(), rules_.size());
    return rules.size();
}

void RuleEngine::add_rule(std::unique_ptr<CorrelationRule> rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = rule->id;
    rules_[id] = std::move(rule);
    profiles_[id] = RuleProfile{.rule_id = id};
    stats_.dsl_rules++;
    stats_.total_rules++;
}

bool RuleEngine::remove_rule(const std::string& rule_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_id);
    if (it == rules_.end()) return false;
    rules_.erase(it);
    profiles_.erase(rule_id);
    stats_.total_rules--;
    return true;
}

std::vector<const CorrelationRule*> RuleEngine::get_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const CorrelationRule*> result;
    result.reserve(rules_.size());
    for (const auto& [_, rule] : rules_) {
        result.push_back(rule.get());
    }
    return result;
}

size_t RuleEngine::rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

std::vector<RuleProfile> RuleEngine::get_profiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RuleProfile> result;
    result.reserve(profiles_.size());
    for (const auto& [_, profile] : profiles_) {
        result.push_back(profile);
    }
    return result;
}

size_t RuleEngine::reload_sigma_rules(const std::string& dir_path) {
    // Remove existing Sigma rules
    std::lock_guard<std::mutex> lock(mutex_);
    // Clear all and reload
    rules_.clear();
    profiles_.clear();
    stats_ = {};
    // Unlock and reload
    // Note: In production, this would be more granular
    auto rules = sigma_compiler_.compile_directory(dir_path);
    for (auto& rule : rules) {
        std::string id = rule->id;
        rules_[id] = std::move(rule);
        profiles_[id] = RuleProfile{.rule_id = id};
        stats_.sigma_rules++;
        stats_.total_rules++;
    }
    spdlog::info("Rule engine reloaded {} Sigma rules", rules.size());
    return rules.size();
}

RuleEngine::Stats RuleEngine::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

} // namespace aiguard
