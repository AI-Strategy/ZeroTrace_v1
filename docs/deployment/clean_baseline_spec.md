# ZeroTrace Clean Baseline Specification (Rust-WASM)

## Objective
To provide a **deterministic, immutable, and verified** container image for the ZeroTrace Rust Interceptor. This image serves as the "Known Good" state for rapid recovery after a security incident.

## Build Philosophy: "Trust No One"
1.  **Deterministic Builds**: Pins all dependencies (Cargo.lock) and system libraries to exact SHA-256 hashes.
2.  **Multi-Stage 'Distroless'**: The final runtime image contains *only* the binary and glibc, removing shells (`/bin/sh`) and package managers (`apt`, `apk`) to eliminate "Living off the Land" attack vectors.
3.  **Non-Root Execution**: Runs as a specific, low-privilege UID/GID (10001) to prevent container breakouts.

## Specification Details

### Base Image
*   **Builder**: `rust:1.75-bookworm` (Pinned Digest)
*   **Runtime**: `gcr.io/distroless/cc-debian12` (Google's minimal runtime)

### Security Controls
*   **No Shell**: Impossible to `docker exec` into the container.
*   **ReadOnly Filesystem**: Application runs with `--read-only` root fs (except `/tmp` or distinct volumes).
*   **Signed Artifacts**: The final image digest is signed with **Cosign** during the CI/CD pipeline.

## Implementation: `Dockerfile.clean`
(See accompanying file)
