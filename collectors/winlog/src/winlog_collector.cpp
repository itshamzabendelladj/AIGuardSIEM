#include "aiguard/winlog/winlog_collector.h"
#include "aiguard/winlog/winlog_parser.h"
#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")
#endif

namespace aiguard {

WinLogCollector::WinLogCollector(const WinLogCollectorConfig& config)
    : config_(config),
      ring_buffer_(config.ring_buffer_capacity) {

    KafkaProducerConfig kafka_config;
    kafka_config.brokers = config_.kafka_brokers;
    kafka_config.topic = config_.kafka_topic;
    kafka_config.batch_num_messages = config_.batch_size;
    kafka_producer_ = std::make_unique<KafkaProducer>(kafka_config);

    auto& registry = MetricsRegistry::instance();
    events_received_counter_ = &registry.create_counter("winlog_events_received_total");
    events_parsed_counter_ = &registry.create_counter("winlog_events_parsed_total");
    events_produced_counter_ = &registry.create_counter("winlog_events_produced_total");
    parse_error_counter_ = &registry.create_counter("winlog_parse_errors_total");
}

WinLogCollector::~WinLogCollector() {
    stop();
}

bool WinLogCollector::start() {
    if (running_.exchange(true)) return false;

    collection_thread_ = std::thread(&WinLogCollector::collection_loop, this);
    processing_thread_ = std::thread(&WinLogCollector::processing_loop, this);

    spdlog::info("WinLog collector started for {} channels", config_.channels.size());
    return true;
}

void WinLogCollector::stop() {
    if (!running_.exchange(false)) return;
    if (collection_thread_.joinable()) collection_thread_.join();
    if (processing_thread_.joinable()) processing_thread_.join();
    if (kafka_producer_) kafka_producer_->flush(5000);
}

void WinLogCollector::collection_loop() {
#ifdef _WIN32
    // Windows Event Log subscription using EvtSubscribe
    for (const auto& channel : config_.channels) {
        // Create event subscription for each channel
        EVT_SUBSCRIBE_HANDLE sub = EvtSubscribe(
            nullptr,  // Session (local)
            nullptr,  // SignalEvent
            nullptr,  // Channel (will use bookmark)
            L"*",     // Query (all events)
            nullptr,  // Bookmark
            nullptr,  // Context
            nullptr,  // Callback
            EvtSubscribeToFutureEvents
        );
        // Full implementation would use EvtNext to read events
        // and EvtRender to get XML representation
    }
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.poll_interval_ms));
        // Poll for new events using EvtNext
    }
#else
    // Non-Windows: wait for forwarded events via ingest_xml
    spdlog::info("WinLog collector running in forwarded mode (non-Windows)");
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.poll_interval_ms));
    }
#endif
}

void WinLogCollector::ingest_xml(const std::string& xml) {
    events_received_counter_->increment();
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.events_received++;
    }
    ring_buffer_.try_push(xml);
}

void WinLogCollector::processing_loop() {
    std::vector<std::pair<std::string_view, std::string_view>> batch;
    std::vector<std::string> jsons;
    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto xml = ring_buffer_.try_pop();
        if (xml) {
            auto record = WinLogParser::parse_xml(*xml);
            if (!record) {
                parse_error_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.parse_errors++;
                }
                continue;
            }

            events_parsed_counter_->increment();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.events_parsed++;
            }

            auto event = std::make_unique<Event>();
            event->id = Event::generate_id();
            event->timestamp = record->time_created;
            event->source_type = "winlog";
            event->host_name = record->computer_name;
            event->host_id = record->computer_name;
            event->category = WinLogParser::get_category(record->channel, record->event_id);
            event->type = "info";
            event->severity = std::string(severity_to_string(
                WinLogParser::map_level(record->level_value)));
            event->severity_score = static_cast<uint8_t>(
                static_cast<int>(WinLogParser::map_level(record->level_value)) * 20);
            event->dataset = "winlog." + record->channel;
            event->module = "winlog";
            event->process_pid = std::to_string(record->process_id);
            event->user_name = record->user_name;
            event->action = std::to_string(record->event_id);

            event->set_field("winlog.event_id", static_cast<int64_t>(record->event_id));
            event->set_field("winlog.channel", record->channel);
            event->set_field("winlog.provider_name", record->provider_name);
            event->set_field("winlog.provider_guid", record->provider_guid);
            event->set_field("winlog.record_id", static_cast<int64_t>(record->record_id));
            event->set_field("winlog.task", record->task_name);
            event->set_field("winlog.opcode", record->opcode_name);
            event->set_field("winlog.level", record->level);
            event->set_field("winlog.process_id", static_cast<int64_t>(record->process_id));
            event->set_field("winlog.thread_id", static_cast<int64_t>(record->thread_id));
            event->set_field("winlog.user_sid", record->user_sid);
            event->set_field("message", record->message);

            // Add event data fields
            for (const auto& [key, value] : record->event_data) {
                event->set_field("winlog.event_data." + key, value);
            }

            normalizer_.normalize(*event, "winlog");

            jsons.push_back(event->to_json());
            batch.emplace_back(jsons.back(), "");

            if (batch.size() >= config_.batch_size) {
                kafka_producer_->produce_batch(batch);
                events_produced_counter_->increment(batch.size());
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.events_produced += batch.size();
                }
                batch.clear();
                jsons.clear();
                last_flush = std::chrono::steady_clock::now();
            }
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
            if (!batch.empty() && elapsed.count() >= config_.batch_timeout_ms) {
                kafka_producer_->produce_batch(batch);
                events_produced_counter_->increment(batch.size());
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.events_produced += batch.size();
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

WinLogCollector::Stats WinLogCollector::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
