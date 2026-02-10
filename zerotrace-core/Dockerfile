# STAGE 1: Caching & Dependencies
FROM rust:1.75-slim-bookworm as planner
WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# STAGE 2: The Builder (and Tester)
FROM rust:1.75-slim-bookworm as builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo install cargo-chef
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and run extensive tests
COPY . .
ARG RUN_TESTS=false
RUN if [ "$RUN_TESTS" = "true" ] ; then \
    echo "--- RUNNING EXTENSIVE ZEROTRACE TEST SUITE ---" && \
    cargo test --release --lib interceptor::training_data_scrubber ; \
    fi

RUN cargo build --release

# STAGE 3: Final Production Airlock
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zerotrace-core /usr/local/bin/zerotrace

# V56 "Path Jail" Infrastructure (Persistent Media Sandbox)
# Ensure the mount point exists and is writable by the app user.
RUN mkdir -p /app/media && chown -R 1001:1001 /app/media

USER 1001
CMD ["zerotrace"]
