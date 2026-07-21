#include "aiguard/engine/stream_processor.h"
#include <spdlog/spdlog.h>
#include <algorithm>

namespace aiguard {

StreamProcessor::StreamProcessor(const StreamProcessorConfig& config)
    : config_(config),
      event_queue_(4096) {

    // Initialize Kafka consumer
    KafkaConsumerConfig consumer_config;
    consumer_config.brokers = config_.kafka_brokers;
    consumer_config.topics = config_.input_topics;
    consumer_config.group_id = config_.group_id;
    consumer_config.max_poll_records = config_.batch_size;
    consumer_config.enable_auto_commit = false;
    consumer_ = std::make_unique<KafkaConsumer>(consumer_config);

    // Initialize Kafka producer for alerts
    KafkaProducerConfig producer_config;
    producer_config.brokers = config_.kafka_brokers;
    producer_config.topic = config_.output_topic;
    producer_config.batch_num_messages = 1000;
    alert_producer_ = std::make_unique<KafkaProducer>(producer_config);

    // Initialize correlation engine
    correlation_engine_ = std::make_unique<CorrelationEngine>();

    // Initialize window manager
    window_manager_ = std::make_unique<EventWindowManager>();
    window_manager_->set_result_callback([this](const WindowResult& result) {
        if (result.threshold_exceeded) {
            // Create alert from window result
            auto event = std::make_unique<Event>();
            event->id = Event::generate_id();
            event->timestamp = Event::now();
            event->category = "alert";
            event->type = "threshold";
            event->severity = "high";
            event->severity_score = 80;
            event->action = "window_threshold_exceeded";
            event->set_field("alert.window_id", result.window_id);
            event->set_field("alert.window_spec", result.spec_id);
            event->set_field("alert.group_key", result.group_key);
            event->set_field("alert.aggregation_value", result.aggregation_value);
            event->set_field("alert.event_count", static_cast<int64_t>(result.event_count));

            alert_producer_->produce(event->to_json());
            alerts_generated_counter_->increment();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.alerts_generated++;
            }
        }
    });

    // Initialize thread pool
    thread_pool_ = std::make_unique<ThreadPool>(config_.worker_threads);

    // Initialize metrics
    auto& registry = MetricsRegistry::instance();
    events_consumed_counter_ = &registry.create_counter("engine_events_consumed_total");
    events_processed_counter_ = &registry.create_counter("engine_events_processed_total");
    alerts_generated_counter_ = &registry.create_counter("engine_alerts_generated_total");
    correlation_matches_counter_ = &registry.create_counter("engine_correlation_matches_total");
    processing_latency_hist_ = &registry.create_histogram(
        "engine_processing_latency_ms",
        {0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0});

    last_stats_time_ = std::chrono::steady_clock::now();
}

StreamProcessor::~StreamProcessor() {
    stop();
}

bool StreamProcessor::start() {
    if (running_.exchange(true)) return false;

    if (!consumer_->subscribe()) {
        running_ = false;
        return false;
    }

    // Start consumer threads
    for (size_t i = 0; i < 2; ++i) {
        consumer_threads_.emplace_back(&StreamProcessor::consume_loop, this);
    }

    // Start processor threads
    for (size_t i = 0; i < config_.worker_threads; ++i) {
        processor_threads_.emplace_back(&StreamProcessor::process_loop, this);
    }

    // Start checkpoint thread
    checkpoint_thread_ = std::thread(&StreamProcessor::checkpoint_loop, this);

    spdlog::info("Stream processor started with {} consumer threads, {} processor threads",
                 2, config_.worker_threads);
    return true;
}

void StreamProcessor::stop() {
    if (!running_.exchange(false)) return;

    for (auto& t : consumer_threads_) { if (t.joinable()) t.join(); }
    for (auto& t : processor_threads_) { if (t.joinable()) t.join(); }
    if (checkpoint_thread_.joinable()) checkpoint_thread_.join();

    consumer_->commit_sync();
    alert_producer_->flush(5000);
    spdlog::info("Stream processor stopped");
}

void StreamProcessor::add_correlation_rule(std::unique_ptr<CorrelationRule> rule) {
    correlation_engine_->add_rule(std::move(rule));
}

void StreamProcessor::add_window(const WindowSpec& spec) {
    window_manager_->add_window(spec);
}

void StreamProcessor::consume_loop() {
    while (running_.load()) {
        auto messages = consumer_->poll_batch(config_.batch_size, config_.poll_timeout_ms);
        if (messages.empty()) continue;

        for (auto& msg : messages) {
            if (msg.error_code != 0) continue;

            auto event = Event::from_json(msg.payload);
            if (event) {
                events_consumed_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.events_consumed++;
                }

                // Push to event queue
                while (!event_queue_.try_push(std::move(event)) && running_.load()) {
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                }
            }
        }

        // Commit after processing batch
        consumer_->commit_async();
    }
}

void StreamProcessor::process_loop() {
    while (running_.load()) {
        auto event = event_queue_.try_pop();
        if (!event) {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
            continue;
        }

        Timer timer(*processing_latency_hist_);

        // Process through correlation engine
        if (config_.enable_correlation && correlation_engine_) {
            auto alerts = correlation_engine_->process_event(**event);
            for (const auto& alert : alerts) {
                // Serialize alert and send to Kafka
                auto alert_event = std::make_unique<Event>();
                alert_event->id = Event::generate_id();
                alert_event->timestamp = alert.timestamp;
                alert_event->category = "alert";
                alert_event->type = "correlation";
                alert_event->severity = std::string(severity_to_string(alert.severity));
                alert_event->severity_score = alert.severity_score;
                alert_event->action = alert.action;
                alert_event->set_field("alert.id", alert.id);
                alert_event->set_field("alert.rule_id", alert.rule_id);
                alert_event->set_field("alert.rule_name", alert.rule_name);
                alert_event->set_field("alert.description", alert.description);
                alert_event->set_field("alert.mitre_tactic", alert.mitre_tactic);
                alert_event->set_field("alert.mitre_technique", alert.mitre_technique);
                alert_event->set_field("alert.match_count", static_cast<int64_t>(alert.match_count));
                alert_event->set_field("alert.aggregation_key", alert.aggregation_key);

                alert_producer_->produce(alert_event->to_json());
                alerts_generated_counter_->increment();
                correlation_matches_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.alerts_generated++;
                    stats_.correlation_matches++;
                }
            }
        }

        // Process through window manager
        if (config_.enable_windowing && window_manager_) {
            window_manager_->process_event(**event);
        }

        events_processed_counter_->increment();
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.events_processed++;
        }
    }
}

void StreamProcessor::checkpoint_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.checkpoint_interval_ms));

        // Clean up expired correlation state
        if (correlation_engine_) {
            correlation_engine_->cleanup_expired();
        }

        // Expire windows
        if (window_manager_) {
            window_manager_->expire_windows();
        }

        // Update stats
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time_);
        uint64_t current_consumed;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            current_consumed = stats_.events_consumed;
        }
        if (elapsed.count() > 0) {
            uint64_t eps = (current_consumed - last_events_consumed_) / elapsed.count();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.current_eps = eps;
                if (eps > stats_.peak_eps) stats_.peak_eps = eps;
            }
            spdlog::info("Engine stats: {} EPS, {} consumed, {} processed, {} alerts",
                         eps, current_consumed,
                         events_processed_counter_->get(),
                         alerts_generated_counter_->get());
        }
        last_events_consumed_ = current_consumed;
        last_stats_time_ = now;
    }
}

StreamProcessor::Stats StreamProcessor::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
