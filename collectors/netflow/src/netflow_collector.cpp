#include "aiguard/netflow/netflow_collector.h"
#include "aiguard/netflow/netflow_parser.h"
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>

namespace aiguard {

NetFlowCollector::NetFlowCollector(const NetFlowCollectorConfig& config)
    : config_(config),
      ring_buffer_(config.ring_buffer_capacity) {

    KafkaProducerConfig kafka_config;
    kafka_config.brokers = config_.kafka_brokers;
    kafka_config.topic = config_.kafka_topic;
    kafka_config.batch_num_messages = config_.batch_size;
    kafka_producer_ = std::make_unique<KafkaProducer>(kafka_config);

    auto& registry = MetricsRegistry::instance();
    packets_received_counter_ = &registry.create_counter("netflow_packets_received_total");
    records_parsed_counter_ = &registry.create_counter("netflow_records_parsed_total");
    parse_error_counter_ = &registry.create_counter("netflow_parse_errors_total");
    records_produced_counter_ = &registry.create_counter("netflow_records_produced_total");
}

NetFlowCollector::~NetFlowCollector() {
    stop();
}

bool NetFlowCollector::start() {
    if (running_.exchange(true)) return false;

    udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_ < 0) {
        spdlog::error("Failed to create UDP socket: {}", strerror(errno));
        running_ = false;
        return false;
    }

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(udp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    int flags = fcntl(udp_socket_, F_GETFL, 0);
    fcntl(udp_socket_, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.udp_port);
    inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

    if (bind(udp_socket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        spdlog::error("Failed to bind UDP socket: {}", strerror(errno));
        close(udp_socket_);
        running_ = false;
        return false;
    }

    for (size_t i = 0; i < config_.worker_threads; ++i) {
        receiver_threads_.emplace_back(&NetFlowCollector::receive_loop, this);
    }
    processing_thread_ = std::thread(&NetFlowCollector::processing_loop, this);

    spdlog::info("NetFlow collector listening on {}:{}", config_.bind_address, config_.udp_port);
    return true;
}

void NetFlowCollector::stop() {
    if (!running_.exchange(false)) return;
    if (udp_socket_ >= 0) { close(udp_socket_); udp_socket_ = -1; }
    for (auto& t : receiver_threads_) { if (t.joinable()) t.join(); }
    if (processing_thread_.joinable()) processing_thread_.join();
    if (kafka_producer_) kafka_producer_->flush(5000);
}

void NetFlowCollector::receive_loop() {
    std::vector<uint8_t> buffer(config_.buffer_size);
    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = udp_socket_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;

        ssize_t recv_len = recvfrom(udp_socket_, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (recv_len <= 0) continue;

        packets_received_counter_->increment();
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_received++;
        }

        std::vector<uint8_t> data(buffer.begin(), buffer.begin() + recv_len);
        if (!ring_buffer_.try_push(std::move(data))) {
            spdlog::warn("NetFlow ring buffer full, dropping packet");
        }
    }
}

void NetFlowCollector::processing_loop() {
    std::vector<std::pair<std::string_view, std::string_view>> batch;
    std::vector<std::string> jsons;
    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto data = ring_buffer_.try_pop();
        if (data) {
            auto records = NetFlowParser::parse(data->data(), data->size());
            for (const auto& rec : records) {
                auto event = std::make_unique<Event>();
                event->id = Event::generate_id();
                event->timestamp = Event::now();
                event->source_type = "netflow";
                event->source_ip = NetFlowParser::ip_to_string(rec.src_addr);
                event->source_port = rec.src_port;
                event->destination_ip = NetFlowParser::ip_to_string(rec.dst_addr);
                event->destination_port = rec.dst_port;
                event->network_transport = NetFlowParser::protocol_to_string(rec.protocol);
                event->network_bytes_in = rec.d_octets;
                event->network_packets_in = rec.d_pkts;
                event->category = "network";
                event->type = "flow";
                event->dataset = "netflow.flow";
                event->module = "netflow";

                event->set_field("netflow.input_if", static_cast<int64_t>(rec.input_if));
                event->set_field("netflow.output_if", static_cast<int64_t>(rec.output_if));
                event->set_field("netflow.tcp_flags", NetFlowParser::tcp_flags_to_string(rec.tcp_flags));
                event->set_field("netflow.tos", static_cast<int64_t>(rec.tos));
                event->set_field("netflow.src_as", static_cast<int64_t>(rec.src_as));
                event->set_field("netflow.dst_as", static_cast<int64_t>(rec.dst_as));

                normalizer_.normalize(*event, "netflow");

                jsons.push_back(event->to_json());
                batch.emplace_back(jsons.back(), "");

                records_parsed_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.records_parsed++;
                }

                if (batch.size() >= config_.batch_size) {
                    kafka_producer_->produce_batch(batch);
                    records_produced_counter_->increment(batch.size());
                    {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.records_produced += batch.size();
                    }
                    batch.clear();
                    jsons.clear();
                    last_flush = std::chrono::steady_clock::now();
                }
            }
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
            if (!batch.empty() && elapsed.count() >= config_.batch_timeout_ms) {
                kafka_producer_->produce_batch(batch);
                records_produced_counter_->increment(batch.size());
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.records_produced += batch.size();
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

NetFlowCollector::Stats NetFlowCollector::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
