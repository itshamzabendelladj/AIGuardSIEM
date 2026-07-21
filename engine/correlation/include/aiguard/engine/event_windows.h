#pragma once

#include "aiguard/common/event.h"
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <functional>
#include <atomic>

namespace aiguard {

/// Window type
enum class WindowType {
    Tumbling,   // Fixed-size, non-overlapping
    Sliding,    // Fixed-size, overlapping
    Session,    // Gap-based
    Hopping     // Fixed-size, hopping advance
};

/// Window specification
struct WindowSpec {
    std::string id;
    WindowType type{WindowType::Tumbling};
    int64_t window_size_ms{60000};      // Window duration
    int64_t slide_size_ms{10000};       // Slide/hop interval (for sliding/hopping)
    int64_t gap_timeout_ms{30000};      // Session gap timeout
    std::string group_by_field;         // Field to group events by
    std::string aggregation_function;   // count, sum, avg, min, max
    std::string aggregation_field;      // Field to aggregate
    double threshold{0.0};              // Alert threshold
    std::string alert_rule_id;          // Rule to trigger when threshold exceeded
};

/// Window result
struct WindowResult {
    std::string window_id;
    std::string spec_id;
    std::chrono::system_clock::time_point window_start;
    std::chrono::system_clock::time_point window_end;
    std::string group_key;
    double aggregation_value{0.0};
    size_t event_count{0};
    bool threshold_exceeded{false};
};

/// Event window manager
///
/// Supports:
/// - Tumbling windows (fixed-size, non-overlapping)
/// - Sliding windows (fixed-size, overlapping)
/// - Session windows (gap-based)
/// - Hopping windows (fixed-size, hopping advance)
/// - Group-by aggregation
/// - Threshold-based alerting
class EventWindowManager {
public:
    using ResultCallback = std::function<void(const WindowResult&)>;

    EventWindowManager();
    ~EventWindowManager() = default;

    /// Add a window specification
    void add_window(const WindowSpec& spec);

    /// Process an event through all windows
    void process_event(const Event& event);

    /// Set callback for window results
    void set_result_callback(ResultCallback callback);

    /// Expire old windows and emit results
    std::vector<WindowResult> expire_windows();

    /// Get active window count
    [[nodiscard]] size_t active_window_count() const;

    /// Clear all windows
    void clear();

private:
    /// Tumbling window processing
    void process_tumbling(const WindowSpec& spec, const Event& event,
                          const std::string& group_key);

    /// Sliding window processing
    void process_sliding(const WindowSpec& spec, const Event& event,
                         const std::string& group_key);

    /// Session window processing
    void process_session(const WindowSpec& spec, const Event& event,
                         const std::string& group_key);

    /// Hopping window processing
    void process_hopping(const WindowSpec& spec, const Event& event,
                         const std::string& group_key);

    /// Aggregate events in a window
    double aggregate(const std::vector<const Event*>& events,
                     const std::string& function,
                     const std::string& field) const;

    /// Get field value as double
    double get_field_double(const Event& event, const std::string& field) const;

    /// Get group key from event
    std::string get_group_key(const Event& event, const std::string& field) const;

    struct WindowState {
        std::chrono::system_clock::time_point start;
        std::chrono::system_clock::time_point end;
        std::vector<std::unique_ptr<Event>> events;
        std::string group_key;
        double last_aggregation{0.0};
    };

    std::vector<WindowSpec> specs_;
    std::unordered_map<std::string, std::unordered_map<std::string, WindowState>> windows_;
    mutable std::mutex mutex_;
    ResultCallback callback_;
};

} // namespace aiguard
