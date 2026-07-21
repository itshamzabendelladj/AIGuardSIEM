#include "aiguard/syslog/syslog_collector.h"
#include "aiguard/syslog/syslog_parser.h"

#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>
#include <poll.h>
#include <algorithm>

namespace aiguard {

SyslogCollector::SyslogCollector(const SyslogCollectorConfig& config)
    : config_(config),
      ring_buffer_(config.ring_buffer_capacity) {

    // Initialize Kafka producer
    KafkaProducerConfig kafka_config;
    kafka_config.brokers = config_.kafka_brokers;
    kafka_config.topic = config_.kafka_topic;
    kafka_config.queue_buffering_max_messages = 1000000;
    kafka_config.queue_buffering_max_ms = config_.batch_timeout_ms;
    kafka_config.batch_num_messages = config_.batch_size;
    kafka_producer_ = std::make_unique<KafkaProducer>(kafka_config);

    // Initialize metrics
    auto& registry = MetricsRegistry::instance();
    messages_received_counter_ = &registry.create_counter("syslog_messages_received_total");
    messages_parsed_counter_ = &registry.create_counter("syslog_messages_parsed_total");
    messages_produced_counter_ = &registry.create_counter("syslog_messages_produced_total");
    parse_error_counter_ = &registry.create_counter("syslog_parse_errors_total");
    processing_latency_hist_ = &registry.create_histogram(
        "syslog_processing_latency_ms", {0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0});
    batch_size_hist_ = &registry.create_histogram(
        "syslog_batch_size", {1, 10, 50, 100, 500, 1000, 5000, 10000});

    last_stats_time_ = std::chrono::steady_clock::now();
}

SyslogCollector::~SyslogCollector() {
    stop();
}

bool SyslogCollector::start() {
    if (running_.exchange(true)) {
        spdlog::warn("Syslog collector already running");
        return false;
    }

    bool success = false;

    // Create UDP socket
    if (config_.transport == SyslogTransport::UDP || config_.transport == SyslogTransport::TCP) {
        udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket_ < 0) {
            spdlog::error("Failed to create UDP socket: {}", strerror(errno));
            running_ = false;
            return false;
        }

        // Set socket options
        int rcvbuf = config_.socket_receive_buffer_bytes;
        setsockopt(udp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        if (config_.enable_non_blocking) {
            int flags = fcntl(udp_socket_, F_GETFL, 0);
            fcntl(udp_socket_, F_SETFL, flags | O_NONBLOCK);
        }

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

        success = true;
        spdlog::info("Syslog UDP collector listening on {}:{}", config_.bind_address, config_.udp_port);

        // Start UDP receiver threads
        for (size_t i = 0; i < config_.worker_threads; ++i) {
            receiver_threads_.emplace_back(&SyslogCollector::udp_receive_loop, this);
        }
    }

    // Create TCP socket if needed
    if (config_.transport == SyslogTransport::TCP || config_.transport == SyslogTransport::TLS) {
        tcp_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_socket_ < 0) {
            spdlog::error("Failed to create TCP socket: {}", strerror(errno));
        } else {
            int reuse = 1;
            setsockopt(tcp_socket_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(config_.tcp_port);
            inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

            if (bind(tcp_socket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
                spdlog::error("Failed to bind TCP socket: {}", strerror(errno));
                close(tcp_socket_);
                tcp_socket_ = -1;
            } else {
                listen(tcp_socket_, 128);
                success = true;
                spdlog::info("Syslog TCP collector listening on {}:{}", config_.bind_address, config_.tcp_port);
                receiver_threads_.emplace_back(&SyslogCollector::tcp_accept_loop, this);
            }
        }
    }

    if (!success) {
        running_ = false;
        return false;
    }

    // Start processing thread
    processing_thread_ = std::thread(&SyslogCollector::processing_loop, this);

    // Start metrics thread
    if (config_.enable_metrics) {
        metrics_thread_ = std::thread(&SyslogCollector::metrics_loop, this);
    }

    spdlog::info("Syslog collector started with {} receiver threads", config_.worker_threads);
    return true;
}

void SyslogCollector::stop() {
    if (!running_.exchange(false)) return;

    // Close sockets
    if (udp_socket_ >= 0) {
        close(udp_socket_);
        udp_socket_ = -1;
    }
    if (tcp_socket_ >= 0) {
        close(tcp_socket_);
        tcp_socket_ = -1;
    }
    if (tls_socket_ >= 0) {
        close(tls_socket_);
        tls_socket_ = -1;
    }

    // Join threads
    for (auto& t : receiver_threads_) {
        if (t.joinable()) t.join();
    }
    receiver_threads_.clear();

    if (processing_thread_.joinable()) processing_thread_.join();
    if (metrics_thread_.joinable()) metrics_thread_.join();

    // Flush Kafka
    if (kafka_producer_) {
        kafka_producer_->flush(5000);
    }

    spdlog::info("Syslog collector stopped");
}

void SyslogCollector::udp_receive_loop() {
    std::vector<uint8_t> buffer(config_.buffer_size);
    struct sockaddr_in client_addr{};
    socklen_t addr_len = sizeof(client_addr);

    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = udp_socket_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;

        ssize_t recv_len = recvfrom(udp_socket_, buffer.data(), buffer.size(),
                                     0, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
        if (recv_len <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                spdlog::warn("UDP recvfrom error: {}", strerror(errno));
            }
            continue;
        }

        messages_received_counter_->increment();

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_received++;
            stats_.bytes_received += static_cast<uint64_t>(recv_len);
        }

        // Push to ring buffer
        RawMessage msg;
        msg.data.assign(buffer.begin(), buffer.begin() + recv_len);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
        msg.source_ip = ip_str;
        msg.source_port = ntohs(client_addr.sin_port);

        if (!ring_buffer_.try_push(std::move(msg))) {
            spdlog::warn("Ring buffer full, dropping syslog message");
        }
    }
}

void SyslogCollector::tcp_accept_loop() {
    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = tcp_socket_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;

        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(tcp_socket_, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                spdlog::warn("TCP accept error: {}", strerror(errno));
            }
            continue;
        }

        // Handle in a detached thread
        std::thread(&SyslogCollector::tcp_connection_handler, this, client_fd).detach();
    }
}

void SyslogCollector::tcp_connection_handler(int client_fd) {
    std::vector<uint8_t> buffer(config_.buffer_size);

    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) {
            if (ret == 0) continue;  // timeout
            break;
        }

        ssize_t recv_len = recv(client_fd, buffer.data(), buffer.size(), 0);
        if (recv_len <= 0) break;

        messages_received_counter_->increment();
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_received++;
            stats_.bytes_received += static_cast<uint64_t>(recv_len);
        }

        // TCP syslog uses octet framing or newline framing
        size_t start = 0;
        for (size_t i = 0; i < static_cast<size_t>(recv_len); ++i) {
            if (buffer[i] == '\n') {
                RawMessage msg;
                msg.data.assign(buffer.begin() + start, buffer.begin() + i);
                if (!ring_buffer_.try_push(std::move(msg))) {
                    spdlog::warn("Ring buffer full, dropping syslog message");
                }
                start = i + 1;
            }
        }
        if (start < static_cast<size_t>(recv_len)) {
            RawMessage msg;
            msg.data.assign(buffer.begin() + start, buffer.begin() + recv_len);
            if (!ring_buffer_.try_push(std::move(msg))) {
                spdlog::warn("Ring buffer full, dropping syslog message");
            }
        }
    }

    close(client_fd);
}

void SyslogCollector::tls_accept_loop() {
    spdlog::info("TLS syslog accept loop started");
    // Full TLS implementation would use OpenSSL BIO for accept + handshake
}

void SyslogCollector::processing_loop() {
    std::vector<std::pair<std::string_view, std::string_view>> batch;
    batch.reserve(config_.batch_size);
    std::vector<std::string> json_strings;
    json_strings.reserve(config_.batch_size);

    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto msg = ring_buffer_.try_pop();
        if (msg) {
            Timer timer(*processing_latency_hist_);

            auto parsed = SyslogParser::parse(msg->data.data(), msg->data.size());
            if (!parsed) {
                parse_error_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.parse_errors++;
                }
                continue;
            }

            messages_parsed_counter_->increment();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.messages_parsed++;
            }

            // Create ECS event
            auto event = std::make_unique<Event>();
            event->id = Event::generate_id();
            event->timestamp = Event::now();
            event->source_type = "syslog";
            event->source_ip = msg->source_ip;
            event->source_port = msg->source_port;
            event->host_name = parsed->hostname;
            event->process_name = parsed->app_name;
            event->source_host = parsed->hostname;
            event->category = "log";
            event->type = "info";
            event->action = parsed->app_name;
            event->severity = std::string(severity_to_string(
                SyslogParser::map_severity(parsed->severity)));
            event->dataset = "syslog." + std::string(SyslogParser::facility_to_string(parsed->facility));
            event->module = "syslog";

            event->set_field("log.syslog.facility.code", static_cast<int64_t>(parsed->facility));
            event->set_field("log.syslog.priority", static_cast<int64_t>(parsed->priority));
            event->set_field("log.syslog.severity.code", static_cast<int64_t>(parsed->severity));
            event->set_field("message", parsed->message);
            if (!parsed->proc_id.empty()) {
                event->set_field("log.syslog.procid", parsed->proc_id);
            }
            if (!parsed->msg_id.empty()) {
                event->set_field("log.syslog.msgid", parsed->msg_id);
            }

            if (!parsed->structured_data.empty()) {
                auto sd = SyslogParser::parse_structured_data(parsed->structured_data);
                for (const auto& [key, value] : sd) {
                    event->set_field("log.syslog.sd." + key, value);
                }
            }

            normalizer_.normalize(*event, "syslog");

            json_strings.push_back(event->to_json());
            batch.emplace_back(json_strings.back(), "");

            if (batch.size() >= config_.batch_size) {
                batch_size_hist_->observe(static_cast<double>(batch.size()));
                size_t produced = kafka_producer_->produce_batch(batch);
                messages_produced_counter_->increment(produced);
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.messages_produced += produced;
                }
                batch.clear();
                json_strings.clear();
                last_flush = std::chrono::steady_clock::now();
            }
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
            if (!batch.empty() && elapsed.count() >= config_.batch_timeout_ms) {
                batch_size_hist_->observe(static_cast<double>(batch.size()));
                size_t produced = kafka_producer_->produce_batch(batch);
                messages_produced_counter_->increment(produced);
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.messages_produced += produced;
                }
                batch.clear();
                json_strings.clear();
                last_flush = now;
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    }

    // Flush remaining batch
    if (!batch.empty()) {
        size_t produced = kafka_producer_->produce_batch(batch);
        messages_produced_counter_->increment(produced);
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_produced += produced;
        }
    }
}

void SyslogCollector::metrics_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time_);

        uint64_t current_received;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            current_received = stats_.messages_received;
        }

        if (elapsed.count() > 0) {
            uint64_t eps = (current_received - last_messages_received_) / elapsed.count();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.current_eps = eps;
                if (eps > stats_.peak_eps) {
                    stats_.peak_eps = eps;
                }
            }
            spdlog::info("Syslog collector stats: {} EPS, {} total received, {} produced",
                         eps, current_received, messages_produced_counter_->get());
        }

        last_messages_received_ = current_received;
        last_stats_time_ = now;
    }
}

SyslogCollector::Stats SyslogCollector::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
