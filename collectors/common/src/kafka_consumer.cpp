#include "aiguard/common/kafka_consumer.h"
#include <librdkafka/rdkafka.h>
#include <spdlog/spdlog.h>
#include <cstring>

namespace aiguard {

KafkaConsumer::KafkaConsumer(const KafkaConsumerConfig& config) : config_(config) {
    rd_kafka_conf_t* conf = rd_kafka_conf_new();
    char errstr[512];

    auto set = [&](const char* key, const std::string& val) {
        if (!val.empty()) {
            if (rd_kafka_conf_set(conf, key, val.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                spdlog::warn("Kafka consumer config '{}': {}", key, errstr);
            }
        }
    };

    set("bootstrap.servers", config_.brokers);
    set("group.id", config_.group_id);
    set("session.timeout.ms", std::to_string(config_.session_timeout_ms));
    set("fetch.min.bytes", std::to_string(config_.fetch_min_bytes));
    set("fetch.max.bytes", std::to_string(config_.fetch_max_bytes));
    set("max.poll.records", std::to_string(config_.max_poll_records));
    set("enable.auto.commit", config_.enable_auto_commit ? "true" : "false");
    set("auto.commit.interval.ms", std::to_string(config_.auto_commit_interval_ms));

    // Offset reset
    const char* offset_str = "latest";
    switch (config_.auto_offset_reset) {
        case 0: offset_str = "earliest"; break;
        case 1: offset_str = "latest"; break;
        default: offset_str = "latest"; break;
    }
    set("auto.offset.reset", offset_str);

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

    // Rebalance callback
    rd_kafka_conf_set_rebalance_cb(conf, &KafkaConsumer::rebalance_callback);

    handle_ = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!handle_) {
        spdlog::error("Failed to create Kafka consumer: {}", errstr);
        throw std::runtime_error("Failed to create Kafka consumer: " + std::string(errstr));
    }

    // Redirect per-partition consumption to queue
    rd_kafka_poll_set_consumer(handle_);
    running_.store(true);
    spdlog::info("Kafka consumer created for group: {}", config_.group_id);
}

KafkaConsumer::~KafkaConsumer() {
    close();
}

bool KafkaConsumer::subscribe() {
    rd_kafka_topic_partition_list_t* topics =
        rd_kafka_topic_partition_list_new(static_cast<int>(config_.topics.size()));
    for (const auto& topic : config_.topics) {
        rd_kafka_topic_partition_list_add(topics, topic.c_str(), -1);
    }

    rd_kafka_resp_err_t err = rd_kafka_subscribe(handle_, topics);
    rd_kafka_topic_partition_list_destroy(topics);

    if (err) {
        spdlog::error("Failed to subscribe to topics: {}", rd_kafka_err2str(err));
        return false;
    }

    spdlog::info("Kafka consumer subscribed to {} topics", config_.topics.size());
    return true;
}

std::optional<KafkaMessage> KafkaConsumer::poll(int timeout_ms) {
    rd_kafka_message_t* msg = rd_kafka_consumer_poll(handle_, timeout_ms);
    if (!msg) return std::nullopt;

    KafkaMessage result;
    result.error_code = msg->err;
    if (msg->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        result.error_string = rd_kafka_err2str(msg->err);
        rd_kafka_message_destroy(msg);
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.error_count++;
        }
        return result;
    }

    if (msg->payload) {
        result.payload = std::string(static_cast<const char*>(msg->payload), msg->len);
    }
    if (msg->key) {
        result.key = std::string(static_cast<const char*>(msg->key), msg->key_len);
    }
    result.topic = rd_kafka_topic_name(msg->rkt);
    result.partition = msg->partition;
    result.offset = msg->offset;
    result.timestamp = rd_kafka_message_timestamp(msg, nullptr);

    rd_kafka_message_destroy(msg);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_consumed++;
        stats_.bytes_consumed += result.payload.size();
    }

    return result;
}

std::vector<KafkaMessage> KafkaConsumer::poll_batch(size_t max_messages, int timeout_ms) {
    std::vector<KafkaMessage> messages;
    messages.reserve(std::min(max_messages, static_cast<size_t>(config_.max_poll_records)));

    // First poll with full timeout
    auto msg = poll(timeout_ms);
    if (!msg) return messages;

    messages.push_back(std::move(*msg));

    // Subsequent polls with zero timeout (drain the queue)
    while (messages.size() < max_messages) {
        msg = poll(0);
        if (!msg) break;
        if (msg->error_code != 0) {
            // Don't let errors abort the batch, but log
            spdlog::warn("Kafka consumer error in batch: {}", msg->error_string);
            continue;
        }
        messages.push_back(std::move(*msg));
    }

    return messages;
}

bool KafkaConsumer::commit_sync() {
    rd_kafka_resp_err_t err = rd_kafka_commit(handle_, nullptr, false);
    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        spdlog::error("Failed to commit offsets: {}", rd_kafka_err2str(err));
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.commit_count++;
    }
    return true;
}

bool KafkaConsumer::commit_async() {
    rd_kafka_resp_err_t err = rd_kafka_commit(handle_, nullptr, true);
    if (err != RD_KAFKA_RESP_ERR_NO_ERROR && err != RD_KAFKA_RESP_ERR__IN_PROGRESS) {
        spdlog::error("Failed to commit offsets async: {}", rd_kafka_err2str(err));
        return false;
    }
    return true;
}

void KafkaConsumer::pause(const std::vector<std::pair<std::string, int>>& partitions) {
    rd_kafka_topic_partition_list_t* list =
        rd_kafka_topic_partition_list_new(static_cast<int>(partitions.size()));
    for (const auto& [topic, part] : partitions) {
        rd_kafka_topic_partition_list_add(list, topic.c_str(), part);
    }
    rd_kafka_pause_partitions(handle_, list);
    rd_kafka_topic_partition_list_destroy(list);
}

void KafkaConsumer::resume(const std::vector<std::pair<std::string, int>>& partitions) {
    rd_kafka_topic_partition_list_t* list =
        rd_kafka_topic_partition_list_new(static_cast<int>(partitions.size()));
    for (const auto& [topic, part] : partitions) {
        rd_kafka_topic_partition_list_add(list, topic.c_str(), part);
    }
    rd_kafka_resume_partitions(handle_, list);
    rd_kafka_topic_partition_list_destroy(list);
}

std::vector<KafkaConsumer::LagInfo> KafkaConsumer::get_lag() const {
    std::vector<LagInfo> result;
    rd_kafka_topic_partition_list_t* partitions = nullptr;

    rd_kafka_resp_err_t err = rd_kafka_assignment(handle_, &partitions);
    if (err || !partitions) return result;

    // Query committed offsets
    rd_kafka_resp_err_t commit_err = rd_kafka_committed(handle_, partitions, 5000);
    if (commit_err) {
        rd_kafka_topic_partition_list_destroy(partitions);
        return result;
    }

    for (int i = 0; i < partitions->cnt; ++i) {
        LagInfo info;
        info.topic = partitions->elems[i].topic;
        info.partition = partitions->elems[i].partition;
        info.current_offset = partitions->elems[i].offset;

        // Query watermark (log end offset)
        int64_t lo, hi;
        rd_kafka_query_watermark_offsets(handle_, info.topic.c_str(),
                                          info.partition, &lo, &hi, 5000);
        info.log_end_offset = hi;
        info.lag = hi - info.current_offset;
        result.push_back(info);
    }

    rd_kafka_topic_partition_list_destroy(partitions);
    return result;
}

KafkaConsumer::Stats KafkaConsumer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void KafkaConsumer::close() {
    if (!running_.exchange(false)) return;
    rd_kafka_consumer_close(handle_);
}

void KafkaConsumer::rebalance_callback(rd_kafka_t* rk, int err,
                                        rd_kafka_topic_partition_list_t* partitions,
                                        void* opaque) {
    auto* self = static_cast<KafkaConsumer*>(opaque);
    if (!self) return;

    switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
            spdlog::info("Kafka rebalance: assigned {} partitions", partitions->cnt);
            rd_kafka_assign(rk, partitions);
            break;
        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
            spdlog::info("Kafka rebalance: revoked {} partitions", partitions->cnt);
            rd_kafka_assign(rk, nullptr);
            break;
        default:
            spdlog::warn("Kafka rebalance error: {}", rd_kafka_err2str(static_cast<rd_kafka_resp_err_t>(err)));
            rd_kafka_assign(rk, nullptr);
            break;
    }
}

} // namespace aiguard
