# Build Stage
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime Stage (Distroless for security)
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/zerotrace-core /app/zerotrace-core
WORKDIR /app
CMD ["./zerotrace-core"]
