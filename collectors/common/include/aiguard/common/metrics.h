#pragma once

#include <atomic>
#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace aiguard {

/// Counter metric - monotonically increasing value
class Counter {
public:
    Counter() = default;
    explicit Counter(std::string name) : name_(std::move(name)) {}

    void increment(uint64_t value = 1) {
        value_.fetch_add(value, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get() const {
        return value_.load(std::memory_order_relaxed);
    }

    void reset() { value_.store(0, std::memory_order_relaxed); }

    [[nodiscard]] const std::string& name() const { return name_; }

private:
    std::string name_;
    std::atomic<uint64_t> value_{0};
};

/// Gauge metric - value that can go up or down
class Gauge {
public:
    Gauge() = default;
    explicit Gauge(std::string name) : name_(std::move(name)) {}

    void set(double value) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ = value;
    }

    void increment(double delta = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ += delta;
    }

    void decrement(double delta = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ -= delta;
    }

    [[nodiscard]] double get() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return value_;
    }

    [[nodiscard]] const std::string& name() const { return name_; }

private:
    std::string name_;
    double value_{0.0};
    mutable std::mutex mutex_;
};

/// Histogram metric for tracking distributions
class Histogram {
public:
    Histogram(std::string name, std::vector<double> bucket_boundaries)
        : name_(std::move(name)),
          bucket_boundaries_(std::move(bucket_boundaries)),
          bucket_counts_(bucket_boundaries_.size() + 1, 0) {}

    void observe(double value) {
        std::lock_guard<std::mutex> lock(mutex_);
        sum_ += value;
        count_++;

        for (size_t i = 0; i < bucket_boundaries_.size(); ++i) {
            if (value <= bucket_boundaries_[i]) {
                bucket_counts_[i]++;
                return;
            }
        }
        bucket_counts_[bucket_counts_.size() - 1]++;
    }

    struct Snapshot {
        double sum;
        uint64_t count;
        std::vector<uint64_t> bucket_counts;
        double p50;
        double p90;
        double p99;
    };

    [[nodiscard]] Snapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Snapshot s;
        s.sum = sum_;
        s.count = count_;
        s.bucket_counts = bucket_counts_;
        s.p50 = percentile_locked(0.5);
        s.p90 = percentile_locked(0.9);
        s.p99 = percentile_locked(0.99);
        return s;
    }

    [[nodiscard]] const std::string& name() const { return name_; }

private:
    double percentile_locked(double p) const {
        if (count_ == 0) return 0.0;
        uint64_t target = static_cast<uint64_t>(p * count_);
        uint64_t cumulative = 0;
        for (size_t i = 0; i < bucket_counts_.size(); ++i) {
            cumulative += bucket_counts_[i];
            if (cumulative >= target) {
                if (i < bucket_boundaries_.size()) {
                    return bucket_boundaries_[i];
                }
                return bucket_boundaries_.back();
            }
        }
        return bucket_boundaries_.back();
    }

    std::string name_;
    std::vector<double> bucket_boundaries_;
    std::vector<uint64_t> bucket_counts_;
    double sum_{0.0};
    uint64_t count_{0};
    mutable std::mutex mutex_;
};

/// Metrics registry - collects and exports metrics
class MetricsRegistry {
public:
    static MetricsRegistry& instance();

    Counter& create_counter(const std::string& name);
    Gauge& create_gauge(const std::string& name);
    Histogram& create_histogram(const std::string& name,
                                 std::vector<double> boundaries);

    [[nodiscard]] std::string export_prometheus() const;

private:
    MetricsRegistry() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<Counter>> counters_;
    std::unordered_map<std::string, std::unique_ptr<Gauge>> gauges_;
    std::unordered_map<std::string, std::unique_ptr<Histogram>> histograms_;
};

/// Timer RAII helper for measuring durations
class Timer {
public:
    using Clock = std::chrono::steady_clock;

    explicit Timer(Histogram& histogram)
        : histogram_(histogram), start_(Clock::now()) {}

    ~Timer() {
        auto duration = std::chrono::duration<double, std::milli>(
            Clock::now() - start_).count();
        histogram_.observe(duration);
    }

private:
    Histogram& histogram_;
    Clock::time_point start_;
};

} // namespace aiguard
