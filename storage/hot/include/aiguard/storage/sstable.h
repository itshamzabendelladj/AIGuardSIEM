#pragma once

#include "aiguard/storage/lsm_index.h"
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <optional>

namespace aiguard {

/// SSTable (Sorted String Table) - immutable sorted file on disk
///
/// Format:
/// [Data Block 1][Data Block 2]...[Data Block N]
/// [Index Block][Filter Block][Footer]
class SSTable {
public:
    SSTable(const std::string& filename, int level, int file_number);
    ~SSTable();

    /// Create SSTable from memtable entries
    static std::unique_ptr<SSTable> create(
        const std::string& filename,
        const std::vector<LSMEntry>& entries,
        bool enable_bloom_filter = true,
        bool enable_compression = true);

    /// Open existing SSTable
    static std::unique_ptr<SSTable> open(const std::string& filename);

    /// Get a value by key
    std::optional<std::string> get(const std::string& key) const;

    /// Range scan
    std::vector<LSMEntry> range(const std::string& start, const std::string& end, size_t limit = 1000) const;

    /// Get file size
    [[nodiscard]] size_t file_size() const { return file_size_; }

    /// Get level
    [[nodiscard]] int level() const { return level_; }

    /// Get file number
    [[nodiscard]] int file_number() const { return file_number_; }

    /// Get smallest key
    [[nodiscard]] const std::string& smallest_key() const { return smallest_key_; }

    /// Get largest key
    [[nodiscard]] const std::string& largest_key() const { return largest_key_; }

    /// Check if key might exist (bloom filter)
    [[nodiscard]] bool might_contain(const std::string& key) const;

private:
    std::string filename_;
    int level_;
    int file_number_;
    size_t file_size_{0};
    std::string smallest_key_;
    std::string largest_key_;

    // Index: key -> offset in file
    std::map<std::string, size_t> index_;

    // Bloom filter
    std::vector<uint8_t> bloom_filter_;
    size_t bloom_bits_{0};

    mutable std::mutex mutex_;

    /// Write bloom filter
    void write_bloom_filter(const std::vector<std::string>& keys);

    /// Read bloom filter
    void read_bloom_filter(std::ifstream& file);

    /// Hash function for bloom filter
    static uint32_t bloom_hash(const std::string& key, uint32_t seed);
};

} // namespace aiguard
