# ZeroTrace v1.0: Engineering Deployment Roadmap

## Phase 1: The Substrate (Weeks 1–2)

**Goal:** Establish the "Memory" and "Identity" layers.

* **Neo4j Schema Deployment:** Implement the **Agent Stability Index (ASI)** nodes. Every interaction must be stored as a `(:Prompt)-[:PRODUCED {logic_hash: "..."}]->(:Response)`.
* **Rust Middleware Core:** Build the basic `tokio` fan-out mesh. Integrate the **Identity-Bound Proxy** to assign every agent a non-human identity (NHI).
* **WORM Ledger Initialization:** Set up the append-only audit log (using `chattr +a` on Linux or a dedicated cloud logging bucket with a lock policy).

## Phase 2: The Sentry & Triage (Weeks 3–4)

**Goal:** Implement the 50ms Speculative Router.

* **Tier 1 Integration:** Load the **Aho-Corasick** and **RegexSet** engines with the first 10 "Fast" vectors (LLM01, LLM07, V33).
* **Tier 2 (Gemini 3 Flash-Lite):** Develop the semantic intent classifier. Fine-tune the "Minimal Thinking" prompt to categorize incoming requests into the three Tiers.
* **The Taint Buffer:** Implement the 5-token sliding window buffer in Rust to hold the stream while Tier 2/3 checks finalize.

## Phase 3: The Adversarial Vault & SCIF (Weeks 5–6)

**Goal:** Build the "Blind" testing environment.

* **gVisor/Firecracker Setup:** Configure the **Secure Runner** Docker images with `runtime: runsc` and `cap_drop: ALL`.
* **OCI Registry Lock:** Implement the **Ed25519** signature verification for the encrypted payload blobs.
* **Red-Team Agent Deployment:** Initialize the "Blind Synthesis" agent that iterates on the 42 vectors without human-readable output.

## Phase 4: Behavioral Governance (Weeks 7–8)

**Goal:** Activate the "DBS Protocol" and Semantic Wall.

* **V39 Toxic Combination Logic:** Script the Neo4j triggers that flag when two unprivileged tool outputs are combined in a single context.
* **V36 Entropy Monitor:** Deploy the Shannon Entropy tracker in the Egress Scrubber.
* **Visual Obfuscation Layer:** Implement the "Abstract-Only" telemetry dashboard for forensic review of test failures.

---

## Deployment Guardrails

1. **Fail-Closed:** If the Sentry Broker (Gemini) or the Reasoning Graph (Neo4j) is unreachable, the system must default to **Airlock Mode** (Manual Approval).
2. **No Plaintext:** At no point in the pipeline should an adversarial payload exist as an unencrypted string in a log file.
3. **Audit the Auditor:** The CTO must conduct a weekly "Physical Key" check of the WORM ledger to ensure no state-tampering has occurred.
