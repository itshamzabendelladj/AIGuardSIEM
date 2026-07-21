#pragma once

#include <atomic>
#include <vector>
#include <memory>
#include <optional>
#include <new>
#include <cstring>
#include <iostream>
#include <type_traits>

namespace aiguard {

/// Lock-free single-producer single-consumer circular buffer
///
/// Uses atomic operations for thread-safe access without locks.
/// Designed for high-throughput event passing between threads.
///
/// @tparam T Element type (must be trivially copyable or movable)
/// @tparam Capacity Buffer capacity (must be power of 2)
template<typename T, size_t Capacity>
class LockFreeCircularBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    static_assert(Capacity > 0, "Capacity must be > 0");

public:
    LockFreeCircularBuffer()
        : head_(0), tail_(0) {
        buffer_ = new std::aligned_storage_t<sizeof(T), alignof(T)>[Capacity];
    }

    ~LockFreeCircularBuffer() {
        // Destroy remaining elements
        size_t h = head_.load(std::memory_order_acquire);
        size_t t = tail_.load(std::memory_order_acquire);
        while (h != t) {
            reinterpret_cast<T*>(&buffer_[h])->~T();
            h = (h + 1) & mask_;
        }
        delete[] buffer_;
    }

    LockFreeCircularBuffer(const LockFreeCircularBuffer&) = delete;
    LockFreeCircularBuffer& operator=(const LockFreeCircularBuffer&) = delete;
    LockFreeCircularBuffer(LockFreeCircularBuffer&&) = delete;
    LockFreeCircularBuffer& operator=(LockFreeCircularBuffer&&) = delete;

    /// Try to push an element (producer side)
    /// @return true if pushed, false if buffer is full
    bool try_push(T&& value) {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next_head = (head + 1) & mask_;

        if (next_head == tail_.load(std::memory_order_acquire)) {
            return false;  // buffer full
        }

        new (&buffer_[head]) T(std::move(value));
        head_.store(next_head, std::memory_order_release);
        return true;
    }

    /// Try to push an element (copy)
    bool try_push(const T& value) {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next_head = (head + 1) & mask_;

        if (next_head == tail_.load(std::memory_order_acquire)) {
            return false;
        }

        new (&buffer_[head]) T(value);
        head_.store(next_head, std::memory_order_release);
        return true;
    }

    /// Try to pop an element (consumer side)
    /// @return Optional value (nullopt if empty)
    std::optional<T> try_pop() {
        size_t tail = tail_.load(std::memory_order_relaxed);

        if (tail == head_.load(std::memory_order_acquire)) {
            return std::nullopt;  // buffer empty
        }

        T value = std::move(*reinterpret_cast<T*>(&buffer_[tail]));
        reinterpret_cast<T*>(&buffer_[tail])->~T();
        tail_.store((tail + 1) & mask_, std::memory_order_release);
        return value;
    }

    /// Check if buffer is empty
    [[nodiscard]] bool empty() const {
        return head_.load(std::memory_order_acquire) ==
               tail_.load(std::memory_order_acquire);
    }

    /// Check if buffer is full
    [[nodiscard]] bool full() const {
        size_t head = head_.load(std::memory_order_acquire);
        size_t next_head = (head + 1) & mask_;
        return next_head == tail_.load(std::memory_order_acquire);
    }

    /// Get current number of elements (approximate)
    [[nodiscard]] size_t size() const {
        size_t head = head_.load(std::memory_order_acquire);
        size_t tail = tail_.load(std::memory_order_acquire);
        return (head - tail) & mask_;
    }

    /// Get capacity
    [[nodiscard]] static constexpr size_t capacity() { return Capacity; }

private:
    static constexpr size_t mask_ = Capacity - 1;
    std::aligned_storage_t<sizeof(T), alignof(T)>* buffer_;
    std::atomic<size_t> head_;  // written by producer
    std::atomic<size_t> tail_;  // written by consumer
};

/// Multi-producer multi-consumer ring buffer with lock
///
/// Used when multiple threads need to produce events.
template<typename T>
class ConcurrentRingBuffer {
public:
    explicit ConcurrentRingBuffer(size_t capacity)
        : capacity_(capacity), mask_(capacity - 1),
          buffer_(capacity), head_(0), tail_(0) {
        if ((capacity & (capacity - 1)) != 0) {
            throw std::runtime_error("Capacity must be power of 2");
        }
    }

    bool try_push(T&& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t next_head = (head_ + 1) & mask_;
        if (next_head == tail_) {
            return false;  // full
        }
        buffer_[head_] = std::move(value);
        head_ = next_head;
        return true;
    }

    std::optional<T> try_pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (head_ == tail_) {
            return std::nullopt;  // empty
        }
        T value = std::move(buffer_[tail_]);
        tail_ = (tail_ + 1) & mask_;
        return value;
    }

    [[nodiscard]] size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return (head_ - tail_) & mask_;
    }

    [[nodiscard]] bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return head_ == tail_;
    }

private:
    size_t capacity_;
    size_t mask_;
    std::vector<T> buffer_;
    size_t head_;
    size_t tail_;
    mutable std::mutex mutex_;
};

} // namespace aiguard
