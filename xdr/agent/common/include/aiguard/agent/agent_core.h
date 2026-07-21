#pragma once

#include "aiguard/common/event.h"
#include "aiguard/common/kafka_producer.h"
#include "aiguard/common/config.h"
#include "aiguard/common/metrics.h"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>

namespace aiguard {

/// Endpoint event types
enum class EndpointEventType {
    ProcessStart,
    ProcessStop,
    FileCreate,
    FileModify,
    FileDelete,
    NetworkConnect,
    NetworkListen,
    RegistryModify,
    DnsQuery,
    ScriptExecute,
    ModuleLoad,
    DriverLoad,
    ImageLoad,
    RemoteThread,
    PipeEvent,
    WmiEvent
};

/// Endpoint event
struct EndpointEvent {
    EndpointEventType type;
    std::chrono::system_clock::time_point timestamp;
    std::string host_name;
    std::string host_id;
    std::string process_name;
    uint32_t process_pid{0};
    uint32_t process_ppid{0};
    std::string process_cmd_line;
    std::string process_path;
    std::string user_name;
    std::string user_sid;
    std::string source_ip;
    uint16_t source_port{0};
    std::string destination_ip;
    uint16_t destination_port{0};
    std::string file_path;
    std::string file_hash;
    std::string registry_key;
    std::string registry_value;
    std::string dns_query;
    std::vector<std::string> dns_results;
    std::map<std::string, std::string> additional_fields;
};

/// Agent configuration
struct AgentConfig {
    std::string server_url{"https://aiguard-server:8443"};
    std::string agent_id;
    std::string auth_token;
    std::string kafka_brokers{"localhost:9092"};
    std::string kafka_topic{"aiguard-endpoint"};
    bool enable_process_monitoring{true};
    bool enable_file_monitoring{true};
    bool enable_network_monitoring{true};
    bool enable_registry_monitoring{true};
    bool enable_dns_monitoring{true};
    int heartbeat_interval_seconds{30};
    int event_batch_size{500};
    int event_batch_timeout_ms{100};
    std::vector<std::string> excluded_processes;
    std::vector<std::string> monitored_paths;
    std::string tls_cert_file;
    std::string tls_key_file;
    std::string tls_ca_file;
};

/// XDR endpoint agent core
///
/// Features:
/// - Process, file, network, registry monitoring
/// - Event batching and compression
/// - Heartbeat to management server
/// - Configuration hot-reload
/// - Response action execution
class AgentCore {
public:
    explicit AgentCore(const AgentConfig& config);
    ~AgentCore();

    AgentCore(const AgentCore&) = delete;
    AgentCore& operator=(const AgentCore&) = delete;

    /// Start the agent
    bool start();

    /// Stop the agent
    void stop();

    /// Check if running
    [[nodiscard]] bool is_running() const { return running_.load(); }

    /// Submit an endpoint event
    void submit_event(EndpointEvent event);

    /// Execute a response action
    struct ResponseAction {
        std::string type;  // isolate, kill_process, disable_account, etc.
        std::string target;
        std::map<std::string, std::string> parameters;
    };
    bool execute_action(const ResponseAction& action);

    /// Get agent statistics
    struct Stats {
        uint64_t events_collected{0};
        uint64_t events_sent{0};
        uint64_t actions_executed{0};
        uint64_t heartbeats_sent{0};
    };
    [[nodiscard]] Stats get_stats() const;

private:
    void event_processing_loop();
    void heartbeat_loop();
    std::unique_ptr<Event> convert_endpoint_event(const EndpointEvent& ep_event);

    AgentConfig config_;
    std::atomic<bool> running_{false};
    std::thread processing_thread_;
    std::thread heartbeat_thread_;
    std::unique_ptr<KafkaProducer> kafka_producer_;

    ConcurrentRingBuffer<EndpointEvent> event_queue_;

    Counter* events_collected_counter_{nullptr};
    Counter* events_sent_counter_{nullptr};
    Counter* actions_counter_{nullptr};

    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace aiguard
