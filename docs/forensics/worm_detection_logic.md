# ZeroTrace: Autonomous AI Worm Detection (EMG27)

## The Threat
**Autonomous AI Worms** (Morris II, Crescendo) exploit the connectivity between agents. An attacker injects a prompt into Agent A, which processes it and unwittingly passes a malicious instruction to Agent B, creating a self-propagating infection loop.

## The Strategy: Graph Centrality & Cycle Detection

### 1. The Forensic Graph
We project flat audit logs into a directed graph:
`(:User)-[:INITIATED]->(:Session)-[:CALLED]->(:Agent A)-[:TRIGGERED]->(:Agent B)`

### 2. Detection Logic (Neo4j)

#### A. Cycle Detection (The Loop)
If the graph shows `(A)->(B)->(A)` within a short time window (`< 5 mins`), it indicates likely recursion or an infinite loop attack (Denial of Wallet).
*   **Action**: ZeroTrace Rust Interceptor blocks Agent A's UUID globally.

#### B. Infection Radius (The Blast Zone)
When Agent A is confirmed malicious:
1.  Query all connected Agents: `MATCH (A)-[:TRIGGERED*1..3]->(target)`.
2.  Mark all targets as `Suspected`.
3.  Enforce **Strict Sandbox** (No Internet, No FS) on `Suspected` agents until cleared by admin.

### 3. Automated Immunization
1.  **Extract**: The input payload that triggered the cycle.
2.  **Fingerprint**: Create a SHA-256 hash of the prompt pattern.
3.  **Deploy**: Push the hash to the `verified_signatures` Postgres table with `is_malicious = true`.
4.  **Block**: Implementation is immediate for all users via the Rust Sidecar.
