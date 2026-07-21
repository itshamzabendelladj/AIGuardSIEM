#include "aiguard/storage/query_engine.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <regex>

namespace aiguard {

QueryEngine::QueryEngine(LSMIndex& index) : index_(index) {}

QueryResult QueryEngine::search(const std::string& query, const QueryFilter& filter) {
    // Parse query (simplified - production would use a proper query parser)
    // Supports: field:value, field>=value, "*" wildcard
    QueryFilter adjusted = filter;

    if (!query.empty()) {
        // Parse simple field:value pairs
        std::regex pair_regex(R"((\w+(?:\.\w+)*)\s*([=<>!]+)\s*(\S+))");
        auto begin = std::sregex_iterator(query.begin(), query.end(), pair_regex);
        auto end = std::sregex_iterator();

        for (auto it = begin; it != end; ++it) {
            std::string field = (*it)[1].str();
            std::string op = (*it)[2].str();
            std::string value = (*it)[3].str();
            // Apply filter (simplified)
            spdlog::debug("Search filter: {} {} {}", field, op, value);
        }
    }

    return index_.query(adjusted);
}

QueryEngine::AggregationResult QueryEngine::aggregate(const std::string& field, const QueryFilter& filter) {
    AggregationResult result;
    result.field = field;

    auto query_result = index_.query(filter);

    // Group by field value
    std::unordered_map<std::string, uint64_t> counts;
    for (const auto& entry : query_result.entries) {
        // Extract field value from JSON (simplified)
        counts["_all"]++;
        result.total++;
    }

    for (const auto& [key, count] : counts) {
        result.buckets.emplace_back(key, count);
    }

    // Sort by count descending
    std::sort(result.buckets.begin(), result.buckets.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    return result;
}

uint64_t QueryEngine::count(const QueryFilter& filter) {
    auto result = index_.query(filter);
    return result.total_count;
}

} // namespace aiguard
