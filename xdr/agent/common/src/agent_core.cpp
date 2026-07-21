#include "aiguard/agent/agent_core.h"
#include <spdlog/spdlog.h>
#include <chrono>
#include <random>

namespace aiguard {

static std::string generate_agent_id() {
    std::random_device rd;
    std::stringstream ss;
    ss << "agent-" << std::hex << rd() << rd();
    return ss.str();
}

AgentCore::AgentCore(const AgentConfig& config)
    : config_(config),
      event_queue_(65536) {

    if (config_.agent_id.empty()) {
        config_.agent_id = generate_agent_id();
    }

    KafkaProducerConfig kafka_config;
    kafka_config.brokers = config_.kafka_brokers;
    kafka_config.topic = config_.kafka_topic;
    kafka_config.batch_num_messages = config_.event_batch_size;
    kafka_producer_ = std::make_unique<KafkaProducer>(kafka_config);

    auto& registry = MetricsRegistry::instance();
    events_collected_counter_ = &registry.create_counter("agent_events_collected_total");
    events_sent_counter_ = &registry.create_counter("agent_events_sent_total");
    actions_counter_ = &registry.create_counter("agent_actions_executed_total");
}

AgentCore::~AgentCore() {
    stop();
}

bool AgentCore::start() {
    if (running_.exchange(true)) return false;

    processing_thread_ = std::thread(&AgentCore::event_processing_loop, this);
    heartbeat_thread_ = std::thread(&AgentCore::heartbeat_loop, this);

    spdlog::info("XDR agent started (ID: {})", config_.agent_id);
    return true;
}

void AgentCore::stop() {
    if (!running_.exchange(false)) return;
    if (processing_thread_.joinable()) processing_thread_.join();
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    if (kafka_producer_) kafka_producer_->flush(5000);
    spdlog::info("XDR agent stopped");
}

void AgentCore::submit_event(EndpointEvent event) {
    events_collected_counter_->increment();
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.events_collected++;
    }

    if (!event_queue_.try_push(std::move(event))) {
        spdlog::warn("Agent event queue full, dropping event");
    }
}

std::unique_ptr<Event> AgentCore::convert_endpoint_event(const EndpointEvent& ep_event) {
    auto event = std::make_unique<Event>();
    event->id = Event::generate_id();
    event->timestamp = ep_event.timestamp;
    event->source_type = "endpoint";
    event->host_name = ep_event.host_name;
    event->host_id = ep_event.host_id;
    event->process_name = ep_event.process_name;
    event->process_pid = std::to_string(ep_event.process_pid);
    event->user_name = ep_event.user_name;
    event->source_ip = ep_event.source_ip;
    event->source_port = ep_event.source_port;
    event->destination_ip = ep_event.destination_ip;
    event->destination_port = ep_event.destination_port;

    // Map event type to ECS
    switch (ep_event.type) {
        case EndpointEventType::ProcessStart:
            event->category = "process";
            event->type = "start";
            event->action = "process_started";
            break;
        case EndpointEventType::ProcessStop:
            event->category = "process";
            event->type = "end";
            event->action = "process_terminated";
            break;
        case EndpointEventType::FileCreate:
            event->category = "file";
            event->type = "creation";
            event->action = "file_created";
            break;
        case EndpointEventType::FileModify:
            event->category = "file";
            event->type = "change";
            event->action = "file_modified";
            break;
        case EndpointEventType::FileDelete:
            event->category = "file";
            event->type = "deletion";
            event->action = "file_deleted";
            break;
        case EndpointEventType::NetworkConnect:
            event->category = "network";
            event->type = "connection";
            event->action = "network_connection";
            break;
        case EndpointEventType::NetworkListen:
            event->category = "network";
            event->type = "connection";
            event->action = "network_listen";
            break;
        case EndpointEventType::RegistryModify:
            event->category = "configuration";
            event->type = "change";
            event->action = "registry_modified";
            break;
        case EndpointEventType::DnsQuery:
            event->category = "network";
            event->type = "info";
            event->action = "dns_query";
            break;
        case EndpointEventType::ScriptExecute:
            event->category = "process";
            event->type = "start";
            event->action = "script_executed";
            break;
        case EndpointEventType::ModuleLoad:
            event->category = "driver";
            event->type = "load";
            event->action = "module_loaded";
            break;
        case EndpointEventType::DriverLoad:
            event->category = "driver";
            event->type = "load";
            event->action = "driver_loaded";
            break;
        case EndpointEventType::RemoteThread:
            event->category = "process";
            event->type = "start";
            event->action = "remote_thread_created";
            event->severity = "high";
            break;
        case EndpointEventType::PipeEvent:
            event->category = "process";
            event->type = "info";
            event->action = "pipe_event";
            break;
        case EndpointEventType::WmiEvent:
            event->category = "process";
            event->type = "info";
            event->action = "wmi_event";
            event->severity = "medium";
            break;
    }

    event->dataset = "endpoint." + event->category;
    event->module = "xdr-agent";

    // Add additional fields
    event->set_field("process.pid", static_cast<int64_t>(ep_event.process_pid));
    event->set_field("process.ppid", static_cast<int64_t>(ep_event.process_ppid));
    event->set_field("process.command_line", ep_event.process_cmd_line);
    event->set_field("process.path", ep_event.process_path);
    event->set_field("file.path", ep_event.file_path);
    event->set_field("file.hash", ep_event.file_hash);
    event->set_field("registry.key", ep_event.registry_key);
    event->set_field("registry.value", ep_event.registry_value);
    event->set_field("dns.question.name", ep_event.dns_query);

    if (!ep_event.dns_results.empty()) {
        event->set_field("dns.resolved_ip", ep_event.dns_results);
    }

    for (const auto& [key, value] : ep_event.additional_fields) {
        event->set_field(key, value);
    }

    return event;
}

void AgentCore::event_processing_loop() {
    std::vector<std::pair<std::string_view, std::string_view>> batch;
    std::vector<std::string> jsons;
    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto ep_event = event_queue_.try_pop();
        if (ep_event) {
            auto event = convert_endpoint_event(*ep_event);
            jsons.push_back(event->to_json());
            batch.emplace_back(jsons.back(), "");

            if (batch.size() >= static_cast<size_t>(config_.event_batch_size)) {
                size_t sent = kafka_producer_->produce_batch(batch);
                events_sent_counter_->increment(sent);
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.events_sent += sent;
                }
                batch.clear();
                jsons.clear();
                last_flush = std::chrono::steady_clock::now();
            }
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
            if (!batch.empty() && elapsed.count() >= config_.event_batch_timeout_ms) {
                size_t sent = kafka_producer_->produce_batch(batch);
                events_sent_counter_->increment(sent);
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.events_sent += sent;
                }
                batch.clear();
                jsons.clear();
                last_flush = now;
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    }

    if (!batch.empty()) {
        kafka_producer_->produce_batch(batch);
    }
}

void AgentCore::heartbeat_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(config_.heartbeat_interval_seconds));

        // Send heartbeat event
        auto event = std::make_unique<Event>();
        event->id = Event::generate_id();
        event->timestamp = Event::now();
        event->source_type = "agent";
        event->category = "heartbeat";
        event->type = "info";
        event->action = "heartbeat";
        event->host_name = config_.agent_id;
        event->set_field("agent.id", config_.agent_id);
        event->set_field("agent.version", "1.0.0");
        event->set_field("agent.status", "active");

        kafka_producer_->produce(event->to_json());
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.heartbeats_sent++;
        }
    }
}

bool AgentCore::execute_action(const ResponseAction& action) {
    spdlog::info("Executing response action: {} on {}", action.type, action.target);
    actions_counter_->increment();
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.actions_executed++;
    }

    // Action execution is OS-specific and would be implemented
    // in the platform-specific agent modules
    return true;
}

AgentCore::Stats AgentCore::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
