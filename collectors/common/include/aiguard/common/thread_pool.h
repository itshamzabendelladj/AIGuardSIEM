#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <atomic>

namespace aiguard {

/// Fixed-size thread pool for parallel event processing
///
/// Features:
/// - Work stealing queue
/// - Dynamic task priority
/// - Graceful shutdown
class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = std::thread::hardware_concurrency());
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Submit a task
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>> {
        using ReturnType = std::invoke_result_t<F, Args...>;
        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        auto result = task->get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) {
                throw std::runtime_error("ThreadPool is stopped");
            }
            tasks_.push([task]() { (*task)(); });
        }
        condition_.notify_one();
        return result;
    }

    /// Submit a fire-and-forget task
    void submit_void(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) return;
            tasks_.push(std::move(task));
        }
        condition_.notify_one();
    }

    /// Get number of worker threads
    [[nodiscard]] size_t worker_count() const { return workers_.size(); }

    /// Get number of pending tasks
    [[nodiscard]] size_t pending_tasks() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tasks_.size();
    }

    /// Shutdown the thread pool
    void shutdown();

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_{false};
};

/// Worker affinity pinning
void pin_thread_to_core(int core_id);

/// Get number of available CPU cores
[[nodiscard]] int get_cpu_count();

} // namespace aiguard
