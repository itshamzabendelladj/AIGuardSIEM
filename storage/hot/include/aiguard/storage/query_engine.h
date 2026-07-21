#pragma once

#include "aiguard/storage/lsm_index.h"
#include <string>
#include <vector>
#include <memory>

namespace aiguard {

/// Query engine for searching events in hot storage
///
/// Features:
/// - Full-text search on event fields
/// - Time-range queries
/// - Field-specific filters
/// - Aggregations (count, group-by)
/// - Pagination with cursors
class QueryEngine {
public:
    explicit QueryEngine(LSMIndex& index);
    ~QueryEngine() = default;

    /// Search events
    QueryResult search(const std::string& query, const QueryFilter& filter);

    /// Aggregate events
    struct AggregationResult {
        std::string field;
        std::vector<std::pair<std::string, uint64_t>> buckets;
        uint64_t total{0};
    };
    AggregationResult aggregate(const std::string& field, const QueryFilter& filter);

    /// Count events matching filter
    uint64_t count(const QueryFilter& filter);

private:
    LSMIndex& index_;
};

} // namespace aiguard
