FROM rust:1.94-slim AS builder

WORKDIR /build

RUN apt-get update && \
  apt-get install -y pkg-config libssl-dev && \
  rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM ubuntu:24.04

RUN apt-get update && \
  apt-get install -y ca-certificates libssl3 && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/reverssh /app/
COPY config /config

RUN mkdir -p /app/logs /certs /config/authorized_keys && \
  chmod +x /app/reverssh

EXPOSE 22

CMD ["/app/reverssh"]
