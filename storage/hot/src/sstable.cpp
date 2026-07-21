#include "aiguard/storage/sstable.h"
#include <spdlog/spdlog.h>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <fstream>

namespace aiguard {

uint32_t SSTable::bloom_hash(const std::string& key, uint32_t seed) {
    // MurmurHash3-style hash
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    uint32_t h = seed;

    const auto* data = reinterpret_cast<const uint8_t*>(key.data());
    size_t len = key.size();

    for (size_t i = 0; i < len; ++i) {
        uint32_t k = data[i];
        k *= c1;
        k = (k << 15) | (k >> 17);
        k *= c2;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }

    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

void SSTable::write_bloom_filter(const std::vector<std::string>& keys) {
    if (keys.empty()) return;

    bloom_bits_ = keys.size() * 10;  // 10 bits per key
    size_t num_bytes = (bloom_bits_ + 7) / 8;
    bloom_filter_.assign(num_bytes, 0);

    // Use 3 hash functions
    for (const auto& key : keys) {
        for (uint32_t seed = 0; seed < 3; ++seed) {
            uint32_t hash = bloom_hash(key, seed);
            uint32_t bit = hash % bloom_bits_;
            bloom_filter_[bit / 8] |= (1 << (bit % 8));
        }
    }
}

void SSTable::read_bloom_filter(std::ifstream& file) {
    // Read bloom filter from end of file
    // Format: [data blocks][index block][bloom filter block][footer]
    // Footer: bloom_bits(8) + bloom_size(8) + index_offset(8) + index_count(8) + magic(8)
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();

    if (file_size < 40) return;

    file.seekg(file_size - 40);
    uint64_t bloom_bits, bloom_size, index_offset, index_count, magic;
    file.read(reinterpret_cast<char*>(&bloom_bits), 8);
    file.read(reinterpret_cast<char*>(&bloom_size), 8);
    file.read(reinterpret_cast<char*>(&index_offset), 8);
    file.read(reinterpret_cast<char*>(&index_count), 8);
    file.read(reinterpret_cast<char*>(&magic), 8);

    if (magic != 0xA1GU4RD5157) return;  // Invalid magic

    bloom_bits_ = bloom_bits;

    // Read bloom filter
    file.seekg(index_offset - bloom_size);
    bloom_filter_.resize(bloom_size);
    file.read(reinterpret_cast<char*>(bloom_filter_.data()), bloom_size);

    // Read index
    file.seekg(index_offset);
    for (uint64_t i = 0; i < index_count; ++i) {
        uint32_t key_len;
        file.read(reinterpret_cast<char*>(&key_len), 4);
        std::string key(key_len, '\0');
        file.read(key.data(), key_len);
        uint64_t offset;
        file.read(reinterpret_cast<char*>(&offset), 8);
        index_[key] = offset;
    }

    if (!index_.empty()) {
        smallest_key_ = index_.begin()->first;
        largest_key_ = index_.rbegin()->first;
    }
}

bool SSTable::might_contain(const std::string& key) const {
    if (bloom_filter_.empty() || bloom_bits_ == 0) return true;

    for (uint32_t seed = 0; seed < 3; ++seed) {
        uint32_t hash = bloom_hash(key, seed);
        uint32_t bit = hash % bloom_bits_;
        if (!(bloom_filter_[bit / 8] & (1 << (bit % 8)))) {
            return false;
        }
    }
    return true;
}

SSTable::SSTable(const std::string& filename, int level, int file_number)
    : filename_(filename), level_(level), file_number_(file_number) {}

SSTable::~SSTable() = default;

std::unique_ptr<SSTable> SSTable::create(const std::string& filename,
                                          const std::vector<LSMEntry>& entries,
                                          bool enable_bloom_filter,
                                          bool enable_compression) {
    auto sstable = std::make_unique<SSTable>(filename, 0, 0);
    sstable->filename_ = filename;

    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        spdlog::error("Failed to create SSTable file: {}", filename);
        return nullptr;
    }

    // Write data blocks and build index
    std::vector<std::string> keys;
    size_t current_offset = 0;

    for (const auto& entry : entries) {
        // Write: key_len(4) + key + value_len(4) + value + seq(8) + deleted(1) + timestamp(8)
        uint32_t key_len = static_cast<uint32_t>(entry.key.size());
        uint32_t val_len = static_cast<uint32_t>(entry.value.size());
        uint64_t seq = entry.sequence_number;
        uint8_t deleted = entry.deleted ? 1 : 0;
        int64_t ts = std::chrono::duration_cast<std::chrono::microseconds>(
            entry.timestamp.time_since_epoch()).count();

        sstable->index_[entry.key] = current_offset;
        keys.push_back(entry.key);

        file.write(reinterpret_cast<const char*>(&key_len), 4);
        file.write(entry.key.data(), key_len);
        file.write(reinterpret_cast<const char*>(&val_len), 4);
        file.write(entry.value.data(), val_len);
        file.write(reinterpret_cast<const char*>(&seq), 8);
        file.write(reinterpret_cast<const char*>(&deleted), 1);
        file.write(reinterpret_cast<const char*>(&ts), 8);

        current_offset += 4 + key_len + 4 + val_len + 8 + 1 + 8;
    }

    // Write bloom filter
    if (enable_bloom_filter) {
        sstable->write_bloom_filter(keys);
    }

    uint64_t index_offset = current_offset;

    // Write bloom filter to file
    uint64_t bloom_size = sstable->bloom_filter_.size();
    file.write(reinterpret_cast<const char*>(sstable->bloom_filter_.data()), bloom_size);

    // Write index
    uint64_t index_count = sstable->index_.size();
    for (const auto& [key, offset] : sstable->index_) {
        uint32_t key_len = static_cast<uint32_t>(key.size());
        file.write(reinterpret_cast<const char*>(&key_len), 4);
        file.write(key.data(), key_len);
        file.write(reinterpret_cast<const char*>(&offset), 8);
    }

    // Write footer
    uint64_t bloom_bits = sstable->bloom_bits_;
    uint64_t magic = 0xA1GU4RD5157;
    file.write(reinterpret_cast<const char*>(&bloom_bits), 8);
    file.write(reinterpret_cast<const char*>(&bloom_size), 8);
    file.write(reinterpret_cast<const char*>(&index_offset), 8);
    file.write(reinterpret_cast<const char*>(&index_count), 8);
    file.write(reinterpret_cast<const char*>(&magic), 8);

    file.close();

    sstable->file_size_ = std::filesystem::file_size(filename);
    if (!entries.empty()) {
        sstable->smallest_key_ = entries.front().key;
        sstable->largest_key_ = entries.back().key;
    }

    spdlog::debug("SSTable created: {} ({} entries, {} bytes)",
                  filename, entries.size(), sstable->file_size_);
    return sstable;
}

std::unique_ptr<SSTable> SSTable::open(const std::string& filename) {
    auto sstable = std::make_unique<SSTable>(filename, 0, 0);
    sstable->filename_ = filename;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        spdlog::error("Failed to open SSTable: {}", filename);
        return nullptr;
    }

    sstable->read_bloom_filter(file);
    sstable->file_size_ = std::filesystem::file_size(filename);

    return sstable;
}

std::optional<std::string> SSTable::get(const std::string& key) const {
    // Check bloom filter first
    if (!might_contain(key)) return std::nullopt;

    // Find in index
    auto it = index_.lower_bound(key);
    if (it == index_.end() || it->first != key) {
        // Check if exact match exists
        it = index_.find(key);
        if (it == index_.end()) return std::nullopt;
    }

    // Read from file
    std::ifstream file(filename_, std::ios::binary);
    if (!file.is_open()) return std::nullopt;

    file.seekg(it->second);
    uint32_t key_len, val_len;
    file.read(reinterpret_cast<char*>(&key_len), 4);
    std::string read_key(key_len, '\0');
    file.read(read_key.data(), key_len);
    if (read_key != key) return std::nullopt;

    file.read(reinterpret_cast<char*>(&val_len), 4);
    std::string value(val_len, '\0');
    file.read(value.data(), val_len);

    uint64_t seq;
    uint8_t deleted;
    file.read(reinterpret_cast<char*>(&seq), 8);
    file.read(reinterpret_cast<char*>(&deleted), 1);

    if (deleted) return std::nullopt;
    return value;
}

std::vector<LSMEntry> SSTable::range(const std::string& start, const std::string& end, size_t limit) const {
    std::vector<LSMEntry> result;
    std::ifstream file(filename_, std::ios::binary);
    if (!file.is_open()) return result;

    // Iterate through index entries in range
    for (auto it = index_.lower_bound(start); it != index_.end() && it->first < end && result.size() < limit; ++it) {
        file.seekg(it->second);
        uint32_t key_len, val_len;
        file.read(reinterpret_cast<char*>(&key_len), 4);
        std::string key(key_len, '\0');
        file.read(key.data(), key_len);
        file.read(reinterpret_cast<char*>(&val_len), 4);
        std::string value(val_len, '\0');
        file.read(value.data(), val_len);

        uint64_t seq;
        uint8_t deleted;
        int64_t ts;
        file.read(reinterpret_cast<char*>(&seq), 8);
        file.read(reinterpret_cast<char*>(&deleted), 1);
        file.read(reinterpret_cast<char*>(&ts), 8);

        if (!deleted) {
            LSMEntry entry;
            entry.key = key;
            entry.value = value;
            entry.sequence_number = seq;
            entry.deleted = false;
            entry.timestamp = std::chrono::system_clock::time_point(std::chrono::microseconds(ts));
            result.push_back(std::move(entry));
        }
    }

    return result;
}

} // namespace aiguard
