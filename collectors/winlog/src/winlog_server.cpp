#include "aiguard/winlog/winlog_collector.h"
#include "aiguard/common/config.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running{true};
void signal_handler(int) { g_running.store(false); }

int main(int argc, char* argv[]) {
    auto logger = spdlog::stdout_color_mt("aiguard-winlog");
    spdlog::set_default_logger(logger);

    spdlog::info("AIGuardSIEM Windows Event Log Collector v1.0.0");
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string config_file = "/etc/aiguard/winlog_collector.yaml";
    if (argc > 1) config_file = argv[1];

    aiguard::Config config(config_file);
    aiguard::WinLogCollectorConfig wc;
    wc.kafka_brokers = config.get_string("kafka.brokers").value_or("localhost:9092");
    wc.kafka_topic = config.get_string("kafka.winlog_topic").value_or("aiguard-winlog");
    auto channels = config.get_string_list("collector.channels");
    if (channels) wc.channels = *channels;

    aiguard::WinLogCollector collector(wc);
    if (!collector.start()) return 1;

    while (g_running.load()) std::this_thread::sleep_for(std::chrono::seconds(1));
    collector.stop();
    return 0;
}
