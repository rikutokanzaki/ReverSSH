FROM rust:slim

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests/e2e.rs ./tests/e2e.rs

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["cargo", "test", "--locked", "--test", "e2e", "--", "--nocapture"]
