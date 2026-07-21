#include "aiguard/common/metrics.h"
#include <sstream>
#include <algorithm>
#include <spdlog/spdlog.h>

namespace aiguard {

MetricsRegistry& MetricsRegistry::instance() {
    static MetricsRegistry instance;
    return instance;
}

Counter& MetricsRegistry::create_counter(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& ptr = counters_[name];
    if (!ptr) {
        ptr = std::make_unique<Counter>(name);
    }
    return *ptr;
}

Gauge& MetricsRegistry::create_gauge(const std::string& full_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& ptr = gauges_[full_name];
    if (!ptr) {
        ptr = std::make_unique<Gauge>(full_name);
    }
    return *ptr;
}

Histogram& MetricsRegistry::create_histogram(const std::string& name,
                                              std::vector<double> boundaries) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& ptr = histograms_[name];
    if (!ptr) {
        ptr = std::make_unique<Histogram>(name, std::move(boundaries));
    }
    return *ptr;
}

std::string MetricsRegistry::export_prometheus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;

    for (const auto& [name, counter] : counters_) {
        oss << "# TYPE " << name << " counter\n";
        oss << name << " " << counter->get() << "\n";
    }

    for (const auto& [name, gauge] : gauges_) {
        oss << "# TYPE " << name << " gauge\n";
        oss << name << " " << gauge->get() << "\n";
    }

    for (const auto& [name, hist] : histograms_) {
        auto snap = hist->snapshot();
        oss << "# TYPE " << name << " histogram\n";
        oss << name << "_count " << snap.count << "\n";
        oss << name << "_sum " << snap.sum << "\n";
        oss << name << "{quantile=\"0.5\"} " << snap.p50 << "\n";
        oss << name << "{quantile=\"0.9\"} " << snap.p90 << "\n";
        oss << name << "{quantile=\"0.99\"} " << snap.p99 << "\n";
    }

    return oss.str();
}

} // namespace aiguard
