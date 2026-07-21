#include "aiguard/agent/agent_core.h"
#include <spdlog/spdlog.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#endif

namespace aiguard {

/// Linux kernel probe (kprobe) monitor
///
/// Monitors kernel function calls for security-relevant events:
/// - process_exec: Process execution
/// - sys_connect: Network connections
/// - sys_open: File access
/// - sys_unlink: File deletion
///
/// Uses /sys/kernel/tracing/ interface or perf events.
class KprobeMonitor {
public:
    KprobeMonitor() = default;
    ~KprobeMonitor() { stop(); }

    /// Initialize kprobes
    bool initialize() {
#ifdef __linux__
        // Enable tracing
        tracing_fd_ = open("/sys/kernel/tracing/trace", O_RDWR);
        if (tracing_fd_ < 0) {
            tracing_fd_ = open("/sys/kernel/debug/tracing/trace", O_RDWR);
        }
        if (tracing_fd_ < 0) {
            spdlog::warn("Failed to open tracing interface: {}", strerror(errno));
            return false;
        }

        // Set up kprobes via kprobe_events
        kprobe_events_fd_ = open("/sys/kernel/tracing/kprobe_events", O_WRONLY);
        if (kprobe_events_fd_ < 0) {
            kprobe_events_fd_ = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY);
        }

        if (kprobe_events_fd_ >= 0) {
            // Register kprobes for key syscalls
            write_kprobe("p:proc_exec do_execveat");
            write_kprobe("p:sys_connect __x64_sys_connect");
            write_kprobe("p:sys_open __x64_sys_openat");
            write_kprobe("p:sys_unlink __x64_sys_unlinkat");
            write_kprobe("p:sys_kill __x64_sys_kill");
            close(kprobe_events_fd_);
            kprobe_events_fd_ = -1;
        }

        // Enable tracing
        int enable_fd = open("/sys/kernel/tracing/events/enable", O_WRONLY);
        if (enable_fd < 0) {
            enable_fd = open("/sys/kernel/debug/tracing/events/enable", O_WRONLY);
        }
        if (enable_fd >= 0) {
            write(enable_fd, "1", 1);
            close(enable_fd);
        }

        spdlog::info("Kprobe monitor initialized");
        return true;
#else
        spdlog::warn("Kprobe monitor not available on this platform");
        return false;
#endif
    }

    /// Start monitoring
    bool start() {
        if (running_.exchange(true)) return false;
        monitor_thread_ = std::thread(&KprobeMonitor::monitor_loop, this);
        return true;
    }

    /// Stop monitoring
    void stop() {
        if (!running_.exchange(false)) return;
        if (monitor_thread_.joinable()) monitor_thread_.join();
        if (tracing_fd_ >= 0) { close(tracing_fd_); tracing_fd_ = -1; }
    }

    /// Set callback for events
    using EventCallback = std::function<void(const EndpointEvent&)>;
    void set_callback(EventCallback callback) {
        callback_ = std::move(callback);
    }

private:
    void write_kprobe(const std::string& probe) {
        if (kprobe_events_fd_ >= 0) {
            std::string cmd = probe + "\n";
            write(kprobe_events_fd_, cmd.c_str(), cmd.size());
        }
    }

    void monitor_loop() {
        char buffer[4096];
        while (running_.load()) {
#ifdef __linux__
            if (tracing_fd_ >= 0) {
                lseek(tracing_fd_, 0, SEEK_SET);
                ssize_t len = read(tracing_fd_, buffer, sizeof(buffer) - 1);
                if (len > 0) {
                    buffer[len] = '\0';
                    parse_trace_output(buffer, len);
                }
            }
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void parse_trace_output(const char* data, size_t len) {
        // Parse trace pipe output format:
        // <task>-<pid> [cpu] d... <time>: <event>: <details>
        std::string content(data, len);
        std::istringstream stream(content);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.empty() || line[0] == '#') continue;

            // Parse trace line
            EndpointEvent event;
            event.timestamp = std::chrono::system_clock::now();

            // Extract process name and PID
            auto dash_pos = line.find('-');
            auto bracket_pos = line.find('[');
            if (dash_pos != std::string::npos && bracket_pos != std::string::npos) {
                event.process_name = line.substr(0, dash_pos);
                std::string pid_str = line.substr(dash_pos + 1, bracket_pos - dash_pos - 2);
                try {
                    event.process_pid = std::stoul(pid_str);
                } catch (...) {}
            }

            // Identify event type
            if (line.find("proc_exec") != std::string::npos) {
                event.type = EndpointEventType::ProcessStart;
            } else if (line.find("sys_connect") != std::string::npos) {
                event.type = EndpointEventType::NetworkConnect;
            } else if (line.find("sys_open") != std::string::npos) {
                event.type = EndpointEventType::FileModify;
            } else if (line.find("sys_unlink") != std::string::npos) {
                event.type = EndpointEventType::FileDelete;
            } else if (line.find("sys_kill") != std::string::npos) {
                event.type = EndpointEventType::ProcessStop;
            }

            if (callback_) callback_(event);
        }
    }

    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    int tracing_fd_{-1};
    int kprobe_events_fd_{-1};
    EventCallback callback_;
};

} // namespace aiguard
