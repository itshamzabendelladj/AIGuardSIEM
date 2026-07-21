#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <optional>
#include <functional>

namespace aiguard {

/// LSM-tree entry
struct LSMEntry {
    std::string key;
    std::string value;
    std::chrono::system_clock::time_point timestamp;
    uint64_t sequence_number{0};
    bool deleted{false};
};

/// Query result
struct QueryResult {
    std::vector<LSMEntry> entries;
    bool has_more{false};
    std::string next_cursor;
    uint64_t total_count{0};
    int64_t query_time_ms{0};
};

/// Query filter
struct QueryFilter {
    std::string key_prefix;
    std::string key_start;
    std::string key_end;
    std::chrono::system_clock::time_point time_start;
    std::chrono::system_clock::time_point time_end;
    size_t limit{1000};
    std::string cursor;
    bool reverse{false};
};

/// LSM-tree configuration
struct LSMConfig {
    std::string data_directory{"/var/lib/aiguard/hot"};
    size_t memtable_max_size{64 * 1024 * 1024};  // 64MB
    size_t sstable_max_size{64 * 1024 * 1024};   // 64MB
    int max_level{7};
    size_t compaction_threshold{4};  // SSTables per level to trigger compaction
    bool enable_bloom_filter{true};
    size_t bloom_filter_bits_per_key{10};
    bool enable_compression{true};
    int compression_type{2};  // 0=none, 1=snappy, 2=zstd
    size_t block_cache_size{256 * 1024 * 1024};  // 256MB
    size_t write_buffer_size{64 * 1024 * 1024};
    int max_background_compactions{4};
    int max_background_flushes{2};
    bool sync_writes{false};
};

/// Custom LSM-tree index for sub-millisecond event queries
///
/// Features:
/// - MemTable with skip list for in-memory writes
/// - SSTable with sorted runs on disk
/// - Multi-level compaction (L0-L7)
/// - Bloom filters for fast point lookups
/// - Memory-mapped inverted indices
/// - Time-series optimized range scans
/// - Zstd compression for disk storage
class LSMIndex {
public:
    explicit LSMIndex(const LSMConfig& config);
    ~LSMIndex();

    LSMIndex(const LSMIndex&) = delete;
    LSMIndex& operator=(const LSMIndex&) = delete;

    /// Put a key-value pair
    bool put(const std::string& key, const std::string& value);

    /// Put a batch of key-value pairs
    bool put_batch(const std::vector<std::pair<std::string, std::string>>& batch);

    /// Get a value by key
    std::optional<std::string> get(const std::string& key) const;

    /// Delete a key
    bool delete_key(const std::string& key);

    /// Query with filter
    QueryResult query(const QueryFilter& filter) const;

    /// Range scan
    std::vector<LSMEntry> range(const std::string& start, const std::string& end, size_t limit = 1000) const;

    /// Prefix scan
    std::vector<LSMEntry> prefix_scan(const std::string& prefix, size_t limit = 1000) const;

    /// Flush memtable to disk
    bool flush();

    /// Trigger compaction
    void compact();

    /// Get statistics
    struct Stats {
        uint64_t total_keys{0};
        uint64_t memtable_size{0};
        uint64_t sstable_count{0};
        uint64_t disk_usage_bytes{0};
        uint64_t writes{0};
        uint64_t reads{0};
        uint64_t range_queries{0};
        double avg_write_latency_us{0};
        double avg_read_latency_us{0};
        double avg_range_latency_us{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    LSMConfig config_;
    std::atomic<uint64_t> sequence_counter_{0};
    mutable std::mutex mutex_;
    Stats stats_;
};

} // namespace aiguard
