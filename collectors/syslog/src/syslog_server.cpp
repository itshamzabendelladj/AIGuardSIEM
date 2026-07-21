#include "aiguard/syslog/syslog_collector.h"
#include "aiguard/common/config.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <iostream>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
    g_running.store(false);
}

int main(int argc, char* argv[]) {
    // Initialize logger
    spdlog::set_level(spdlog::level::info);
    auto logger = spdlog::stdout_color_mt("aiguard-syslog");
    spdlog::set_default_logger(logger);

    spdlog::info("AIGuardSIEM Syslog Collector v1.0.0");
    spdlog::info("Starting high-performance syslog collector...");

    // Signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Load configuration
    std::string config_file = "/etc/aiguard/syslog_collector.yaml";
    if (argc > 1) {
        config_file = argv[1];
    }

    aiguard::Config config(config_file);

    aiguard::SyslogCollectorConfig collector_config;
    collector_config.udp_port = static_cast<uint16_t>(config.get_int("collector.udp_port").value_or(514));
    collector_config.tcp_port = static_cast<uint16_t>(config.get_int("collector.tcp_port").value_or(514));
    collector_config.tls_port = static_cast<uint16_t>(config.get_int("collector.tls_port").value_or(6514));
    collector_config.bind_address = config.get_string("collector.bind_address").value_or("0.0.0.0");
    collector_config.worker_threads = config.get_int("collector.worker_threads").value_or(4);
    collector_config.batch_size = config.get_int("collector.batch_size").value_or(1000);
    collector_config.batch_timeout_ms = config.get_int("collector.batch_timeout_ms").value_or(100);
    collector_config.kafka_brokers = config.get_string("kafka.brokers").value_or("localhost:9092");
    collector_config.kafka_topic = config.get_string("kafka.syslog_topic").value_or("aiguard-syslog");
    collector_config.ring_buffer_capacity = config.get_int("collector.ring_buffer_capacity").value_or(1048576);
    collector_config.enable_tls = config.get_bool("collector.enable_tls").value_or(false);
    collector_config.tls_cert_file = config.get_string("collector.tls_cert_file").value_or("");
    collector_config.tls_key_file = config.get_string("collector.tls_key_file").value_or("");
    collector_config.tls_ca_file = config.get_string("collector.tls_ca_file").value_or("");

    // Create and start collector
    aiguard::SyslogCollector collector(collector_config);

    if (!collector.start()) {
        spdlog::error("Failed to start syslog collector");
        return 1;
    }

    // Wait for shutdown signal
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto stats = collector.get_stats();
        spdlog::debug("Stats: {} received, {} parsed, {} produced, {} errors",
                      stats.messages_received, stats.messages_parsed,
                      stats.messages_produced, stats.parse_errors);
    }

    spdlog::info("Shutting down syslog collector...");
    collector.stop();
    spdlog::info("Syslog collector stopped");

    return 0;
}
