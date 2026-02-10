# ZeroTrace Verification Suite

This directory contains the integration and end-to-end tests for the ZeroTrace Infrastructure.

## Strict Testing Hierarchy

### 1. Unit Tests (Rust)
*   **Location**: Co-located in `src/**/*.rs` files (`#[cfg(test)]`).
*   **Purpose**: Verifies individual logic gates (LLM01, Slopsquat, DBS) in isolation.
*   **Command**: `cargo test`

### 2. Integration Tests (Miniflare)
*   **Location**: `tests/verify_dbs.mjs`
*   **Purpose**: Black-box testing of the compiled WASM worker in a Cloudflare simulation.
*   **Command**: `npm test`

## Running Tests

### Unit Tests
```bash
cd zerotrace-core
cargo test
```

### E2E / Integration
```bash
# Ensure dependencies are installed
npm install

# Run the Miniflare suite
npm test
```
