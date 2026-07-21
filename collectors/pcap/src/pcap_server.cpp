#include "aiguard/pcap/dpdk_capture.h"
#include "aiguard/common/config.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running.store(false);
}

int main(int argc, char* argv[]) {
    auto logger = spdlog::stdout_color_mt("aiguard-pcap");
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);

    spdlog::info("AIGuardSIEM Packet Capture v1.0.0");

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string config_file = "/etc/aiguard/pcap_collector.yaml";
    if (argc > 1) config_file = argv[1];

    aiguard::Config config(config_file);

    aiguard::PacketCaptureConfig cap_config;
    cap_config.interface = config.get_string("collector.interface").value_or("eth0");
    cap_config.bpf_filter = config.get_string("collector.bpf_filter").value_or("");
    cap_config.worker_threads = config.get_int("collector.worker_threads").value_or(4);
    cap_config.batch_size = config.get_int("collector.batch_size").value_or(500);
    cap_config.kafka_brokers = config.get_string("kafka.brokers").value_or("localhost:9092");
    cap_config.kafka_topic = config.get_string("kafka.network_topic").value_or("aiguard-network");
    cap_config.extract_flows = config.get_bool("collector.extract_flows").value_or(true);

    std::string mode = config.get_string("collector.mode").value_or("libpcap");
    if (mode == "dpdk") cap_config.mode = aiguard::CaptureMode::DPDK;
    else if (mode == "af_packet") cap_config.mode = aiguard::CaptureMode::AF_PACKET;
    else cap_config.mode = aiguard::CaptureMode::LibPcap;

    aiguard::PacketCapture capture(cap_config);
    if (!capture.start()) {
        spdlog::error("Failed to start packet capture");
        return 1;
    }

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    spdlog::info("Shutting down packet capture...");
    capture.stop();
    return 0;
}
