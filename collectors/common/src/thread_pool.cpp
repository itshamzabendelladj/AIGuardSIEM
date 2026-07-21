#include "aiguard/common/thread_pool.h"
#include <spdlog/spdlog.h>

#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <pthread.h>
#include <sys/sysctl.h>
#endif

namespace aiguard {

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
    }
    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    condition_.wait(lock, [this] {
                        return stop_ || !tasks_.empty();
                    });
                    if (stop_ && tasks_.empty()) {
                        return;
                    }
                    task = std::move(tasks_.front());
                    tasks_.pop();
                }
                try {
                    task();
                } catch (const std::exception& e) {
                    spdlog::error("ThreadPool task exception: {}", e.what());
                }
            }
        });
    }
    spdlog::info("ThreadPool started with {} workers", num_threads);
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_) return;
        stop_ = true;
    }
    condition_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void pin_thread_to_core(int core_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        spdlog::warn("Failed to pin thread to core {}: {}", core_id, rc);
    }
#elif defined(__APPLE__)
    // macOS doesn't support thread affinity in the same way
    (void)core_id;
#endif
}

int get_cpu_count() {
#ifdef __linux__
    return sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(__APPLE__)
    int count;
    size_t size = sizeof(count);
    sysctlbyname("hw.ncpu", &count, &size, nullptr, 0);
    return count;
#else
    return std::thread::hardware_concurrency();
#endif
}

} // namespace aiguard
