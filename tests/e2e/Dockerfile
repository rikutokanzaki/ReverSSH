FROM rust:1.100-slim-bookworm

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests/e2e.rs ./tests/e2e.rs

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 reverssh \
    && useradd --system --uid 10001 --gid reverssh --create-home --home-dir /home/reverssh \
        --shell /usr/sbin/nologin reverssh \
    && mkdir -p /tmp/cargo \
    && chown -R reverssh:reverssh /build /home/reverssh /tmp/cargo

ENV CARGO_HOME=/tmp/cargo
USER reverssh:reverssh

ENTRYPOINT ["cargo", "test", "--locked", "--test", "e2e", "--", "--nocapture"]
