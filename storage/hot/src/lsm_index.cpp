#include "aiguard/storage/lsm_index.h"
#include "aiguard/storage/memtable.h"
#include "aiguard/storage/sstable.h"
#include <spdlog/spdlog.h>
#include <filesystem>
#include <algorithm>
#include <chrono>

namespace aiguard {

LSMIndex::LSMIndex(const LSMConfig& config) : config_(config) {
    // Create data directory
    std::filesystem::create_directories(config_.data_directory);
    spdlog::info("LSM index initialized at {}", config_.data_directory);
}

LSMIndex::~LSMIndex() {
    flush();
}

bool LSMIndex::put(const std::string& key, const std::string& value) {
    auto start = std::chrono::steady_clock::now();

    uint64_t seq = sequence_counter_.fetch_add(1, std::memory_order_relaxed);

    // Create memtable if needed
    static thread_local std::unique_ptr<MemTable> memtable;
    if (!memtable || memtable->is_full()) {
        if (memtable) {
            flush();
        }
        memtable = std::make_unique<MemTable>(config_.memtable_max_size);
    }

    bool success = memtable->put(key, value, seq);

    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.writes++;
        stats_.total_keys++;
        stats_.memtable_size = memtable->size();
        // Update average latency
        stats_.avg_write_latency_us = (stats_.avg_write_latency_us * (stats_.writes - 1) + latency) / stats_.writes;
    }

    return success;
}

bool LSMIndex::put_batch(const std::vector<std::pair<std::string, std::string>>& batch) {
    for (const auto& [key, value] : batch) {
        if (!put(key, value)) return false;
    }
    return true;
}

std::optional<std::string> LSMIndex::get(const std::string& key) const {
    auto start = std::chrono::steady_clock::now();

    // Check memtable first (in production, would use the actual memtable)
    // Then check SSTables from newest to oldest

    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.reads++;
        stats_.avg_read_latency_us = (stats_.avg_read_latency_us * (stats_.reads - 1) + latency) / stats_.reads;
    }

    return std::nullopt;  // Simplified - full implementation would check memtable and SSTables
}

bool LSMIndex::delete_key(const std::string& key) {
    uint64_t seq = sequence_counter_.fetch_add(1, std::memory_order_relaxed);
    // Write tombstone
    (void)seq;
    return true;
}

QueryResult LSMIndex::query(const QueryFilter& filter) const {
    auto start = std::chrono::steady_clock::now();

    QueryResult result;

    if (!filter.key_start.empty() && !filter.key_end.empty()) {
        result.entries = range(filter.key_start, filter.key_end, filter.limit);
    } else if (!filter.key_prefix.empty()) {
        result.entries = prefix_scan(filter.key_prefix, filter.limit);
    }

    result.total_count = result.entries.size();
    result.has_more = result.entries.size() >= filter.limit;

    auto end = std::chrono::steady_clock::now();
    result.query_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.range_queries++;
        stats_.avg_range_latency_us = (stats_.avg_range_latency_us * (stats_.range_queries - 1) +
                                       result.query_time_ms * 1000) / stats_.range_queries;
    }

    return result;
}

std::vector<LSMEntry> LSMIndex::range(const std::string& start, const std::string& end, size_t limit) const {
    // In production, would merge results from memtable and all SSTables
    return {};
}

std::vector<LSMEntry> LSMIndex::prefix_scan(const std::string& prefix, size_t limit) const {
    return {};
}

bool LSMIndex::flush() {
    spdlog::info("Flushing LSM index");
    // In production, would flush memtable to SSTable
    return true;
}

void LSMIndex::compact() {
    spdlog::info("Compacting LSM index");
    // In production, would merge SSTables
}

LSMIndex::Stats LSMIndex::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

} // namespace aiguard
