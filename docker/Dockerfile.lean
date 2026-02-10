# docker/Dockerfile.lean
# ZeroTrace "Airlock" Build
# Optimized for Firecracker MicroVMs (<100ms cold start)

# STEP 1: Build (Cache-optimized)
FROM rust:1.75-slim-bookworm as builder
WORKDIR /app

# Create empty shell project to cache dependencies
RUN cargo new --bin zerotrace-core
WORKDIR /app/zerotrace-core
COPY zerotrace-core/Cargo.toml zerotrace-core/Cargo.lock ./
RUN cargo build --release
RUN rm src/*.rs

# Copy actual source code
COPY zerotrace-core/src ./src
# Touch main.rs to force rebuild
RUN touch src/main.rs
RUN cargo build --release

# STEP 2: Runtime (The 'Airlock')
FROM debian:bookworm-slim

# Install only bare essentials for SSL/TLS (Neo4j Bolt+s requirement)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user (Security Best Practice)
RUN useradd -ms /bin/bash zerotrace
USER zerotrace
WORKDIR /home/zerotrace

COPY --from=builder /app/zerotrace-core/target/release/zerotrace-core /usr/local/bin/zerotrace

ENV PORT=8080
EXPOSE 8080

# Firecracker-optimized boot
CMD ["zerotrace"]
