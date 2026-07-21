#include "aiguard/storage/memtable.h"
#include <spdlog/spdlog.h>
#include <algorithm>

namespace aiguard {

MemTable::MemTable(size_t max_size) : max_size_(max_size) {}

bool MemTable::put(const std::string& key, const std::string& value, uint64_t seq) {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t entry_size = key.size() + value.size() + sizeof(Entry);
    if (current_size_.load() + entry_size > max_size_) {
        return false;  // MemTable full
    }

    auto& entry = entries_[key];
    entry.value = value;
    entry.seq = seq;
    entry.deleted = false;
    entry.timestamp = std::chrono::system_clock::now();
    current_size_ += entry_size;

    return true;
}

std::optional<std::string> MemTable::get(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;
    if (it->second.deleted) return std::nullopt;
    return it->second.value;
}

bool MemTable::remove(const std::string& key, uint64_t seq) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& entry = entries_[key];
    entry.value.clear();
    entry.seq = seq;
    entry.deleted = true;
    entry.timestamp = std::chrono::system_clock::now();
    return true;
}

std::vector<LSMEntry> MemTable::range(const std::string& start, const std::string& end, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LSMEntry> result;

    auto it = entries_.lower_bound(start);
    while (it != entries_.end() && it->first < end && result.size() < limit) {
        if (!it->second.deleted) {
            LSMEntry entry;
            entry.key = it->first;
            entry.value = it->second.value;
            entry.timestamp = it->second.timestamp;
            entry.sequence_number = it->second.seq;
            entry.deleted = it->second.deleted;
            result.push_back(std::move(entry));
        }
        ++it;
    }

    return result;
}

std::vector<LSMEntry> MemTable::prefix_scan(const std::string& prefix, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LSMEntry> result;

    for (auto it = entries_.lower_bound(prefix); it != entries_.end(); ++it) {
        if (!it->first.starts_with(prefix)) break;
        if (result.size() >= limit) break;
        if (!it->second.deleted) {
            LSMEntry entry;
            entry.key = it->first;
            entry.value = it->second.value;
            entry.timestamp = it->second.timestamp;
            entry.sequence_number = it->second.seq;
            entry.deleted = it->second.deleted;
            result.push_back(std::move(entry));
        }
    }

    return result;
}

std::vector<LSMEntry> MemTable::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LSMEntry> result;
    result.reserve(entries_.size());

    for (const auto& [key, entry] : entries_) {
        LSMEntry e;
        e.key = key;
        e.value = entry.value;
        e.timestamp = entry.timestamp;
        e.sequence_number = entry.seq;
        e.deleted = entry.deleted;
        result.push_back(std::move(e));
    }

    return result;
}

size_t MemTable::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

void MemTable::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    current_size_.store(0);
}

} // namespace aiguard
