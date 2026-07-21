FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y \
    build-essential cmake libboost-all-dev libssl-dev \
    librdkafka-dev librocksdb-dev nlohmann-json3-dev \
    libfmt-dev libspdlog-dev
WORKDIR /build
COPY . .
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) aiguard_syslog_collector

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y librdkafka1 libssl3 libboost-system1.74.0 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/build/bin/aiguard_syslog_collector /usr/local/bin/
EXPOSE 514/udp 514/tcp 6514/tcp 9100
CMD ["aiguard_syslog_collector"]
