#include "aiguard/pcap/dpdk_capture.h"
#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>

#ifdef AIGUARD_DPDK_ENABLED
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#endif

namespace aiguard {

PacketCapture::PacketCapture(const PacketCaptureConfig& config)
    : config_(config),
      ring_buffer_(config.ring_buffer_capacity) {

    // Initialize Kafka producer
    KafkaProducerConfig kafka_config;
    kafka_config.brokers = config_.kafka_brokers;
    kafka_config.topic = config_.kafka_topic;
    kafka_config.queue_buffering_max_messages = 500000;
    kafka_config.batch_num_messages = config_.batch_size;
    kafka_producer_ = std::make_unique<KafkaProducer>(kafka_config);

    // Initialize flow tracker
    FlowTrackerConfig flow_config;
    flow_config.collect_payload_samples = config_.extract_payload;
    flow_config.max_payload_sample_size = config_.max_payload_extract;
    flow_tracker_ = std::make_unique<FlowTracker>(flow_config);

    // Initialize metrics
    auto& registry = MetricsRegistry::instance();
    packets_captured_counter_ = &registry.create_counter("pcap_packets_captured_total");
    packets_dropped_counter_ = &registry.create_counter("pcap_packets_dropped_total");
    bytes_captured_counter_ = &registry.create_counter("pcap_bytes_captured_total");
    flows_expired_counter_ = &registry.create_counter("pcap_flows_expired_total");
    capture_latency_hist_ = &registry.create_histogram(
        "pcap_capture_latency_us", {1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000});
    packet_size_hist_ = &registry.create_histogram(
        "pcap_packet_size_bytes",
        {64, 128, 256, 512, 1024, 1518, 4096, 9000, 65535});

    last_stats_time_ = std::chrono::steady_clock::now();
}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start() {
    if (running_.exchange(true)) {
        spdlog::warn("Packet capture already running");
        return false;
    }

    bool success = false;

    switch (config_.mode) {
        case CaptureMode::LibPcap:
            success = true;  // pcap handle opened in capture loop
            for (size_t i = 0; i < config_.worker_threads; ++i) {
                capture_threads_.emplace_back(&PacketCapture::pcap_capture_loop, this);
            }
            break;
        case CaptureMode::DPDK:
#ifdef AIGUARD_DPDK_ENABLED
            success = true;
            capture_threads_.emplace_back(&PacketCapture::dpdk_capture_loop, this);
#else
            spdlog::error("DPDK support not compiled in");
            running_ = false;
            return false;
#endif
            break;
        case CaptureMode::AF_PACKET:
            success = true;
            for (size_t i = 0; i < config_.worker_threads; ++i) {
                capture_threads_.emplace_back(&PacketCapture::af_packet_capture_loop, this);
            }
            break;
        case CaptureMode::PF_RING:
            spdlog::error("PF_RING mode not yet implemented");
            running_ = false;
            return false;
    }

    if (!success) {
        running_ = false;
        return false;
    }

    // Start processing thread
    processing_thread_ = std::thread(&PacketCapture::processing_loop, this);

    // Start flow expiry thread
    if (config_.extract_flows) {
        flow_expiry_thread_ = std::thread(&PacketCapture::flow_expiry_loop, this);
    }

    // Start metrics thread
    if (config_.enable_metrics) {
        metrics_thread_ = std::thread(&PacketCapture::metrics_loop, this);
    }

    spdlog::info("Packet capture started on interface {} with {} threads",
                 config_.interface, config_.worker_threads);
    return true;
}

void PacketCapture::stop() {
    if (!running_.exchange(false)) return;

    for (auto& t : capture_threads_) {
        if (t.joinable()) t.join();
    }
    capture_threads_.clear();

    if (processing_thread_.joinable()) processing_thread_.join();
    if (flow_expiry_thread_.joinable()) flow_expiry_thread_.join();
    if (metrics_thread_.joinable()) metrics_thread_.join();

    if (kafka_producer_) {
        kafka_producer_->flush(5000);
    }

    spdlog::info("Packet capture stopped");
}

void PacketCapture::pcap_capture_loop() {
#ifdef HAVE_LIBPCAP
    #include <pcap.h>
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(config_.interface.c_str(),
                                     config_.snapshot_length,
                                     config_.promiscuous_mode ? 1 : 0,
                                     config_.buffer_timeout_ms,
                                     errbuf);
    if (!handle) {
        spdlog::error("Failed to open interface {}: {}", config_.interface, errbuf);
        return;
    }

    // Set BPF filter if specified
    if (!config_.bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, config_.bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle, &fp);
            pcap_freecode(&fp);
        } else {
            spdlog::warn("Failed to compile BPF filter: {}", pcap_geterr(handle));
        }
    }

    pcap_handle_ = handle;

    struct pcap_pkthdr* header;
    const u_char* data;

    while (running_.load()) {
        int ret = pcap_next_ex(handle, &header, &data);
        if (ret <= 0) {
            if (ret == 0) continue;  // timeout
            spdlog::warn("pcap_next_ex error: {}", pcap_geterr(handle));
            break;
        }

        packets_captured_counter_->increment();
        bytes_captured_counter_->increment(header->caplen);
        packet_size_hist_->observe(static_cast<double>(header->caplen));

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_captured++;
            stats_.bytes_captured += header->caplen;
        }

        RawPacket pkt;
        pkt.data.assign(data, data + header->caplen);
        pkt.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                        std::chrono::microseconds(header->ts.tv_usec);
        pkt.original_length = header->len;

        if (!ring_buffer_.try_push(std::move(pkt))) {
            packets_dropped_counter_->increment();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_dropped++;
            }
        }
    }

    pcap_close(handle);
    pcap_handle_ = nullptr;
#else
    spdlog::error("libpcap not available");
#endif
}

void PacketCapture::dpdk_capture_loop() {
#ifdef AIGUARD_DPDK_ENABLED
    // Initialize DPDK EAL
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("aiguard_pcap"));
    for (auto& arg : config_.dpdk_args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }

    int ret = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (ret < 0) {
        spdlog::error("Failed to initialize DPDK EAL");
        return;
    }

    // Create memory pool
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        config_.dpdk_mempool_size,
        config_.dpdk_mempool_cache_size,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (!mbuf_pool) {
        spdlog::error("Failed to create mbuf pool");
        return;
    }

    // Configure and start Ethernet device
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        spdlog::error("No DPDK ports available");
        return;
    }

    uint16_t port_id = 0;
    struct rte_eth_conf port_conf{};
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        spdlog::error("Failed to configure DPDK port: {}", ret);
        return;
    }

    // Setup RX queue
    ret = rte_eth_rx_queue_setup(port_id, 0, config_.dpdk_ring_size,
                                  rte_eth_dev_socket_id(port_id), nullptr, mbuf_pool);
    if (ret < 0) {
        spdlog::error("Failed to setup RX queue: {}", ret);
        return;
    }

    // Setup TX queue
    ret = rte_eth_tx_queue_setup(port_id, 0, config_.dpdk_ring_size,
                                  rte_eth_dev_socket_id(port_id), nullptr);
    if (ret < 0) {
        spdlog::error("Failed to setup TX queue: {}", ret);
        return;
    }

    // Start device
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        spdlog::error("Failed to start DPDK port: {}", ret);
        return;
    }

    rte_eth_promiscuous_enable(port_id);
    spdlog::info("DPDK capture started on port {}", port_id);

    // Main capture loop
    struct rte_mbuf* bufs[32];
    while (running_.load()) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, config_.dpdk_burst_size);
        for (uint16_t i = 0; i < nb_rx; ++i) {
            packets_captured_counter_->increment();
            bytes_captured_counter_->increment(rte_pktmbuf_pkt_len(bufs[i]));
            packet_size_hist_->observe(static_cast<double>(rte_pktmbuf_pkt_len(bufs[i])));

            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_captured++;
                stats_.bytes_captured += rte_pktmbuf_pkt_len(bufs[i]);
            }

            RawPacket pkt;
            char* data = rte_pktmbuf_mtod(bufs[i], char*);
            size_t len = rte_pktmbuf_pkt_len(bufs[i]);
            pkt.data.assign(data, data + len);
            pkt.timestamp = std::chrono::system_clock::now();
            pkt.original_length = len;

            if (!ring_buffer_.try_push(std::move(pkt))) {
                packets_dropped_counter_->increment();
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.packets_dropped++;
                }
            }

            rte_pktmbuf_free(bufs[i]);
        }
    }

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();
#else
    spdlog::error("DPDK not compiled in. Rebuild with -DAIGUARD_ENABLE_DPDK=ON");
#endif
}

void PacketCapture::af_packet_capture_loop() {
#ifdef __linux__
    #include <sys/socket.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
    #include <net/if.h>
    #include <sys/mman.h>

    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        spdlog::error("Failed to create AF_PACKET socket: {}", strerror(errno));
        return;
    }

    // Bind to interface
    struct sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex(config_.interface.c_str());
    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        spdlog::error("Failed to bind AF_PACKET socket: {}", strerror(errno));
        close(sock);
        return;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Set receive buffer
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    std::vector<uint8_t> buffer(config_.snapshot_length);

    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;

        ssize_t recv_len = recv(sock, buffer.data(), buffer.size(), 0);
        if (recv_len <= 0) continue;

        packets_captured_counter_->increment();
        bytes_captured_counter_->increment(recv_len);
        packet_size_hist_->observe(static_cast<double>(recv_len));

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_captured++;
            stats_.bytes_captured += recv_len;
        }

        RawPacket pkt;
        pkt.data.assign(buffer.begin(), buffer.begin() + recv_len);
        pkt.timestamp = std::chrono::system_clock::now();
        pkt.original_length = recv_len;

        if (!ring_buffer_.try_push(std::move(pkt))) {
            packets_dropped_counter_->increment();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_dropped++;
            }
        }
    }

    close(sock);
#else
    spdlog::error("AF_PACKET only available on Linux");
#endif
}

void PacketCapture::processing_loop() {
    std::vector<std::pair<std::string_view, std::string_view>> batch;
    batch.reserve(config_.batch_size);
    std::vector<std::string> json_strings;
    json_strings.reserve(config_.batch_size);

    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto pkt = ring_buffer_.try_pop();
        if (pkt) {
            Timer timer(*capture_latency_hist_);

            // Update flow tracker
            if (config_.extract_flows && flow_tracker_) {
                flow_tracker_->process_packet(pkt->data.data(), pkt->data.size(),
                                               pkt->timestamp);
            }

            // Create ECS event for the packet
            auto event = std::make_unique<Event>();
            event->id = Event::generate_id();
            event->timestamp = pkt->timestamp;
            event->source_type = "network";
            event->category = "network";
            event->type = "connection";
            event->dataset = "pcap.network";
            event->module = "pcap";
            event->network_bytes_in = pkt->original_length;
            event->raw_data = std::move(pkt->data);

            json_strings.push_back(event->to_json());
            batch.emplace_back(json_strings.back(), "");

            if (batch.size() >= config_.batch_size) {
                kafka_producer_->produce_batch(batch);
                batch.clear();
                json_strings.clear();
                last_flush = std::chrono::steady_clock::now();
            }
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
            if (!batch.empty() && elapsed.count() >= config_.batch_timeout_ms) {
                kafka_producer_->produce_batch(batch);
                batch.clear();
                json_strings.clear();
                last_flush = now;
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
        }
    }

    if (!batch.empty()) {
        kafka_producer_->produce_batch(batch);
    }
}

void PacketCapture::flow_expiry_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        if (!flow_tracker_) continue;

        auto expired = flow_tracker_->expire_flows();
        if (expired.empty()) continue;

        flows_expired_counter_->increment(expired.size());
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.flows_expired += expired.size();
            stats_.flows_active = flow_tracker_->active_flow_count();
        }

        // Publish expired flows to Kafka
        std::vector<std::pair<std::string_view, std::string_view>> batch;
        std::vector<std::string> jsons;
        for (auto& flow : expired) {
            auto event = std::make_unique<Event>();
            event->id = Event::generate_id();
            event->timestamp = Event::now();
            event->source_type = "netflow";
            event->category = "network";
            event->type = "flow";
            event->dataset = "pcap.flow";
            event->module = "pcap";
            event->network_bytes_in = flow.stats.byte_count;
            event->network_packets_in = flow.stats.packet_count;
            event->set_field("flow.duration_ms", flow.stats.duration_ms);
            event->set_field("flow.fwd_packets", static_cast<int64_t>(flow.stats.fwd_packet_count));
            event->set_field("flow.bwd_packets", static_cast<int64_t>(flow.stats.bwd_packet_count));
            event->set_field("flow.syn_count", static_cast<int64_t>(flow.stats.syn_count));
            event->set_field("flow.rst_count", static_cast<int64_t>(flow.stats.rst_count));

            jsons.push_back(event->to_json());
            batch.emplace_back(jsons.back(), "");
        }

        if (!batch.empty()) {
            kafka_producer_->produce_batch(batch);
        }
    }
}

void PacketCapture::metrics_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time_);

        uint64_t current_packets, current_bytes;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            current_packets = stats_.packets_captured;
            current_bytes = stats_.bytes_captured;
        }

        if (elapsed.count() > 0) {
            uint64_t pps = (current_packets - last_packets_) / elapsed.count();
            double bps = static_cast<double>(current_bytes - last_bytes_) / elapsed.count();
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.current_pps = pps;
                stats_.current_bps = bps;
                if (pps > stats_.peak_pps) stats_.peak_pps = pps;
                if (bps > stats_.peak_bps) stats_.peak_bps = bps;
            }
            spdlog::info("PCAP stats: {} pps, {:.2f} bps, {} active flows",
                         pps, bps, flow_tracker_ ? flow_tracker_->active_flow_count() : 0);
        }

        last_packets_ = current_packets;
        last_bytes_ = current_bytes;
        last_stats_time_ = now;
    }
}

PacketCapture::Stats PacketCapture::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace aiguard
