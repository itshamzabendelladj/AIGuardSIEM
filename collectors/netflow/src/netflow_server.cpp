#include "aiguard/netflow/netflow_collector.h"
#include "aiguard/common/config.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running{true};
void signal_handler(int) { g_running.store(false); }

int main(int argc, char* argv[]) {
    auto logger = spdlog::stdout_color_mt("aiguard-netflow");
    spdlog::set_default_logger(logger);

    spdlog::info("AIGuardSIEM NetFlow Collector v1.0.0");
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string config_file = "/etc/aiguard/netflow_collector.yaml";
    if (argc > 1) config_file = argv[1];

    aiguard::Config config(config_file);
    aiguard::NetFlowCollectorConfig nc;
    nc.udp_port = static_cast<uint16_t>(config.get_int("collector.udp_port").value_or(2055));
    nc.bind_address = config.get_string("collector.bind_address").value_or("0.0.0.0");
    nc.kafka_brokers = config.get_string("kafka.brokers").value_or("localhost:9092");
    nc.kafka_topic = config.get_string("kafka.netflow_topic").value_or("aiguard-netflow");

    aiguard::NetFlowCollector collector(nc);
    if (!collector.start()) return 1;

    while (g_running.load()) std::this_thread::sleep_for(std::chrono::seconds(1));
    collector.stop();
    return 0;
}
