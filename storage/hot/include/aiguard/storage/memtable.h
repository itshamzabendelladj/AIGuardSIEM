#pragma once

#include "aiguard/storage/lsm_index.h"
#include <map>
#include <vector>
#include <mutex>
#include <atomic>

namespace aiguard {

/// MemTable - in-memory write buffer using a sorted map
///
/// Uses std::map for ordered key storage and efficient range scans.
/// In production, a concurrent skip list would be used.
class MemTable {
public:
    explicit MemTable(size_t max_size = 64 * 1024 * 1024);
    ~MemTable() = default;

    /// Put a key-value pair
    bool put(const std::string& key, const std::string& value, uint64_t seq);

    /// Get a value by key
    std::optional<std::string> get(const std::string& key) const;

    /// Delete a key (tombstone)
    bool remove(const std::string& key, uint64_t seq);

    /// Range scan
    std::vector<LSMEntry> range(const std::string& start, const std::string& end, size_t limit = 1000) const;

    /// Prefix scan
    std::vector<LSMEntry> prefix_scan(const std::string& prefix, size_t limit = 1000) const;

    /// Get all entries (for flushing)
    std::vector<LSMEntry> get_all() const;

    /// Check if memtable is full
    [[nodiscard]] bool is_full() const { return current_size_.load() >= max_size_; }

    /// Get current size
    [[nodiscard]] size_t size() const { return current_size_.load(); }

    /// Get entry count
    [[nodiscard]] size_t count() const;

    /// Clear the memtable
    void clear();

private:
    struct Entry {
        std::string value;
        uint64_t seq;
        bool deleted;
        std::chrono::system_clock::time_point timestamp;
    };

    std::map<std::string, Entry> entries_;
    mutable std::mutex mutex_;
    std::atomic<size_t> current_size_{0};
    size_t max_size_;
};

} // namespace aiguard
