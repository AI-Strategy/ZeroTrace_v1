# ZeroTrace Deployment Guide (v1.0)

## Overview
This guide covers the deployment of the **ZeroTrace Security Stack**, featuring the **Dual-Stage Parallel Mesh** and **Stateful Firewall** (Neo4j).

## Prerequisites
- **Rust**: v1.75+
- **Neo4j**: v5.0+ (Enterprise or AuraDB)
- **Gemini API Key**: For `Gemini 3 Flash` Speculative Router.
- **PostgreSQL**: v15+ (Forensics Logger)

## 1. Core Component: Parallel Mesh (Rust)
The core security engine resides in `zerotrace-core`. It manages the 38-vectored dual-stage triage.

### Configuration
Update `config/security_manifest.json` with your active vectors.
```bash
# Verify the manifest is valid
cargo test security::parallel_mesh
```

### Build
```bash
cd zerotrace-core
cargo build --release
```

## 2. Stateful Firewall (Neo4j Integration)
The `BehavioralGuard` and `EntropyTracker` require a graph backend to persist session history and agent stability scores.

### Schema Setup
Run the following Cypher queries in Neo4j to initialize the schema:

```cypher
// Create Constraints
CREATE CONSTRAINT FOR (s:Session) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT FOR (a:Agent) REQUIRE a.id IS UNIQUE;

// Indexes for speed
CREATE INDEX FOR (s:Session) ON (s.created_at);
CREATE INDEX FOR (a:Agent) ON (a.stability_index);
```

### Connection
Set environment variables:
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

## 3. Deployment Topology
**Recommended Pattern**: Sidecar Proxy or Ingress Gateway.

1.  **Ingress**: Requests hit `zerotrace-proxy` (Port 8000).
2.  **Parallel Mesh**: Spawns 4 concurrent tasks (Safety, Drift, Policy, Inference).
3.  **Egress**: Validated tokens are streamed back to the client.

## 4. Monitoring & Telemetry
-   **Drift Alerts**: Subscribe to "Amber" tier alerts in the Admin Dashboard.
-   **Entropy Spikes**: Monitor `V36` alerts for potential exfiltration attempts.
-   **Latency**: Ensure the `speculative_router` stays within the 50ms budget (P99).

## 5. Emergency Rollback
If the mesh blocks legitimate traffic ("False Positives"):
1.  Set `fail_open: true` in `config/security_manifest.json`.
2.  Restart the service to bypass the Airlock/Shielded paths temporarily.
