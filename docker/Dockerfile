FROM rust:1.100-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
  apt-get install -y --no-install-recommends pkg-config libssl-dev && \
  apt-get upgrade -y && \
  rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
COPY src ./src

RUN cargo build --locked --release

FROM ubuntu:24.04

RUN apt-get update && \
  apt-get install -y --no-install-recommends ca-certificates libssl3 && \
  apt-get upgrade -y && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/reverssh /app/
COPY config /config

RUN groupadd --system --gid 10001 reverssh && \
  useradd --system --uid 10001 --gid reverssh --create-home --home-dir /home/reverssh \
    --shell /usr/sbin/nologin reverssh && \
  mkdir -p /app/logs /certs /config/authorized_keys /var/log/reverssh && \
  chmod +x /app/reverssh && \
  chown -R reverssh:reverssh /app /certs /config /var/log/reverssh /home/reverssh

USER reverssh:reverssh

EXPOSE 2222

CMD ["/app/reverssh"]
