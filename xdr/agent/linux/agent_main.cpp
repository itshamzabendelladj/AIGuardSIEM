#include "aiguard/agent/agent_core.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <sys/utsname.h>

// Forward declarations from kprobe_monitor.cpp and ebpf_tracer.cpp
namespace aiguard {
class KprobeMonitor {
public:
    bool initialize();
    bool start();
    void stop();
    void set_callback(std::function<void(const EndpointEvent&)>);
};
class EBPFTracer {
public:
    bool initialize();
    bool start();
    void stop();
    void set_callback(std::function<void(const EndpointEvent&)>);
};
}

static std::atomic<bool> g_running{true};
void signal_handler(int) { g_running.store(false); }

int main(int argc, char* argv[]) {
    // Check root privileges
    if (getuid() != 0) {
        fprintf(stderr, "AIGuard XDR agent requires root privileges\n");
        return 1;
    }

    auto logger = spdlog::stdout_color_mt("aiguard-agent");
    spdlog::set_default_logger(logger);

    // Get hostname
    struct utsname uts;
    uname(&uts);

    spdlog::info("AIGuardSIEM XDR Agent v1.0.0 (host: {})", uts.nodename);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Load configuration
    std::string config_file = "/etc/aiguard/agent.yaml";
    if (argc > 1) config_file = argv[1];

    aiguard::Config config(config_file);

    aiguard::AgentConfig agent_config;
    agent_config.kafka_brokers = config.get_string("kafka.brokers").value_or("localhost:9092");
    agent_config.kafka_topic = config.get_string("kafka.endpoint_topic").value_or("aiguard-endpoint");
    agent_config.server_url = config.get_string("agent.server_url").value_or("https://localhost:8443");
    agent_config.enable_process_monitoring = config.get_bool("agent.enable_process_monitoring").value_or(true);
    agent_config.enable_file_monitoring = config.get_bool("agent.enable_file_monitoring").value_or(true);
    agent_config.enable_network_monitoring = config.get_bool("agent.enable_network_monitoring").value_or(true);

    // Initialize agent
    aiguard::AgentCore agent(agent_config);
    agent.start();

    // Initialize kprobe monitor
    aiguard::KprobeMonitor kprobe;
    kprobe.set_callback([&agent](const aiguard::EndpointEvent& event) {
        agent.submit_event(event);
    });
    kprobe.initialize();
    kprobe.start();

    // Initialize eBPF tracer
    aiguard::EBPFTracer ebpf;
    ebpf.set_callback([&agent](const aiguard::EndpointEvent& event) {
        agent.submit_event(event);
    });
    ebpf.initialize();
    ebpf.start();

    spdlog::info("XDR agent running. Press Ctrl+C to stop.");

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto stats = agent.get_stats();
        spdlog::debug("Agent stats: {} collected, {} sent",
                      stats.events_collected, stats.events_sent);
    }

    spdlog::info("Shutting down XDR agent...");
    ebpf.stop();
    kprobe.stop();
    agent.stop();
    spdlog::info("XDR agent stopped");

    return 0;
}
