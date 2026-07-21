#include "aiguard/common/kafka_producer.h"
#include <librdkafka/rdkafka.h>
#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>

namespace aiguard {

KafkaProducer::KafkaProducer(const KafkaProducerConfig& config) : config_(config) {
    rd_kafka_conf_t* conf = rd_kafka_conf_new();
    char errstr[512];

    auto set = [&](const char* key, const std::string& val) {
        if (!val.empty()) {
            if (rd_kafka_conf_set(conf, key, val.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                spdlog::warn("Kafka producer config '{}': {}", key, errstr);
            }
        }
    };

    set("bootstrap.servers", config_.brokers);
    set("queue.buffering.max.messages", std::to_string(config_.queue_buffering_max_messages));
    set("queue.buffering.max.kbytes", std::to_string(config_.queue_buffering_max_kbytes));
    set("queue.buffering.max.ms", std::to_string(config_.queue_buffering_max_ms));
    set("message.timeout.ms", std::to_string(config_.message_timeout_ms));
    set("batch.num.messages", std::to_string(config_.batch_num_messages));
    set("message.max.bytes", std::to_string(config_.message_max_bytes));
    set("message.send.max.retries", std::to_string(config_.message_send_max_retries));
    set("request.required.acks", std::to_string(config_.request_required_acks));

    // Compression
    const char* comp_str = "snappy";
    switch (config_.compression_type) {
        case 2: comp_str = "lz4"; break;
        case 3: comp_str = "zstd"; break;
        case 4: comp_str = "gzip"; break;
        default: comp_str = "snappy"; break;
    }
    set("compression.type", comp_str);

    // Idempotence
    if (config_.enable_idempotence) {
        set("enable.idempotence", "true");
        set("max.in.flight.requests.per.connection", "5");
    }

    // Security
    if (config_.security_protocol != "PLAINTEXT") {
        set("security.protocol", config_.security_protocol);
        set("ssl.ca.location", config_.ssl_ca_location);
        set("ssl.certificate.location", config_.ssl_certificate_location);
        set("ssl.key.location", config_.ssl_key_location);
        if (!config_.sasl_username.empty()) {
            set("sasl.mechanism", config_.sasl_mechanism);
            set("sasl.username", config_.sasl_username);
            set("sasl.password", config_.sasl_password);
        }
    }

    // Delivery report callback
    rd_kafka_conf_set_dr_msg_cb(conf, &KafkaProducer::delivery_report_callback);

    handle_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!handle_) {
        spdlog::error("Failed to create Kafka producer: {}", errstr);
        throw std::runtime_error("Failed to create Kafka producer: " + std::string(errstr));
    }

    topic_ = rd_kafka_topic_new(handle_, config_.topic.c_str(), nullptr);
    if (!topic_) {
        spdlog::error("Failed to create Kafka topic: {}", rd_kafka_err2str(rd_kafka_last_error()));
        rd_kafka_destroy(handle_);
        throw std::runtime_error("Failed to create Kafka topic");
    }

    healthy_.store(true);
    spdlog::info("Kafka producer connected to brokers: {}, topic: {}", config_.brokers, config_.topic);
}

KafkaProducer::~KafkaProducer() {
    flush(config_.flush_timeout_ms);
    if (topic_) rd_kafka_topic_destroy(topic_);
    if (handle_) rd_kafka_destroy(handle_);
}

bool KafkaProducer::produce(std::string_view payload, std::string_view key) {
    if (!healthy_.load(std::memory_order_relaxed)) {
        return false;
    }

    int err = rd_kafka_produce(
        topic_,
        config_.partition,
        RD_KAFKA_MSG_F_COPY,
        const_cast<char*>(payload.data()),
        payload.size(),
        key.empty() ? nullptr : key.data(),
        key.size(),
        nullptr);

    if (err != 0) {
        spdlog::warn("Failed to produce Kafka message: {}", rd_kafka_err2str(rd_kafka_errno2err(errno)));
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_failed++;
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_produced++;
        stats_.bytes_produced += payload.size();
    }
    return true;
}

size_t KafkaProducer::produce_batch(const std::vector<std::pair<std::string_view, std::string_view>>& payloads) {
    size_t success_count = 0;
    for (const auto& [payload, key] : payloads) {
        if (produce(payload, key)) {
            success_count++;
        }
    }
    return success_count;
}

int KafkaProducer::flush(int timeout_ms) {
    return rd_kafka_flush(handle_, timeout_ms);
}

int KafkaProducer::poll(int timeout_ms) {
    return rd_kafka_poll(handle_, timeout_ms);
}

size_t KafkaProducer::queue_size() const {
    return rd_kafka_outq_len(handle_);
}

KafkaProducer::Stats KafkaProducer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void KafkaProducer::set_delivery_callback(DeliveryCallback callback) {
    delivery_callback_ = std::move(callback);
}

bool KafkaProducer::is_healthy() const {
    return healthy_.load(std::memory_order_relaxed);
}

void KafkaProducer::delivery_report_callback(rd_kafka_t* rk, void* payload,
                                              size_t len, int error_code,
                                              void* opaque, void* msg_opaque) {
    auto* self = static_cast<KafkaProducer*>(rd_kafka_opaque(rk));
    if (!self) return;

    {
        std::lock_guard<std::mutex> lock(self->stats_mutex_);
        if (error_code == 0) {
            self->stats_.messages_delivered++;
        } else {
            self->stats_.messages_failed++;
        }
    }

    if (self->delivery_callback_) {
        DeliveryReport report;
        report.error_code = error_code;
        if (error_code != 0) {
            report.error_string = rd_kafka_err2str(static_cast<rd_kafka_resp_err_t>(error_code));
        }
        report.timestamp = std::chrono::system_clock::now();
        self->delivery_callback_(report);
    }
}

} // namespace aiguard
