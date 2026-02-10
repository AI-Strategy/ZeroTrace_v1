# Implementation Plan - EMG21: Multi-Modal Indirect Injection

## Goal Description
Implement **EMG21** mitigation strategy in `ZeroTrace`. This module (`MultiModalGuard`) safeguards against indirect injection through non-text assets (images, PDFs, Audio) by enforcing a **Content Disarm & Reconstruction (CDR)** pipeline.
It ensures:
1.  Metadata is stripped.
2.  Content is reduced to text via isolated engines (OCR/Transcription).
3.  Text is sanitized before LLM consumption.

## User Review Required
> [!NOTE]
> **WASM Constraints**: Since `ZeroTrace` runs on Cloudflare Workers (WASM), heavy operations like native OCR (Tesseract) or sophisticated Image Magick operations are not feasible directly in-process.
> **Architecture Decision**: The `MultiModalGuard` will be implemented defining **Traits** (`AssetProcessor`, `MetadataScrubber`) that abstract these operations. The default implementation will likely call out to external services (or other Workers) or use lightweight WASM-compatible parsers if available. For this task, we will focus on the **Guard Logic** and **Mockable Interfaces** to ensure testability and strict logic flow.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg21.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg21.rs)
- **Struct**: `MultiModalGuard`
- **Traits**:
    - `MetadataScrubber`: Responsible for cleaning bytes.
    - `ContentExtractor`: Responsible for OCR/Transcription.
- **Logic**:
    - `sanitize_asset(bytes, mime)` pipeline.
    - Validation of MIME types.
    - Error handling (`SecurityError`).
- **Enhancements**:
    - Async support (for external calls).
    - Strong typing for supported MIME types.
    - Entropy checks (placeholder).

#### [MODIFY] [lib.rs / mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/lib.rs)
- Register the new module `security`.

## Verification Plan

### Automated Tests
- **Unit Tests**:
    - Test `sanitize_asset` flow with Mock Scrubber/Extractor.
    - Test "Unsupported MIME" rejection.
    - Test "Injection Detected" (simulate "Ignore instructions" in extracted text).
- **Command**: `cargo test security::emg21`

# Implementation Plan - EMG22: Side-Channel Data Exfiltration

## Goal Description
Implement **EMG22** mitigation in `ZeroTrace`. This module (`SideChannelGuard`) prevents side-channel attacks (Timing and Packet Size Analysis) by enforcing:
1.  **Deterministic Timing**: Buffering responses to a fixed minimum duration.
2.  **Length Padding**: Normalizing response sizes to obfuscate content length.

## User Review Required
> [!IMPORTANT]
> **Async Implementation**: The user provided snippet uses `std::thread::sleep`, which blocks the entire thread. Since `ZeroTrace` uses `tokio` and runs on Workers, we **MUST** use `tokio::time::sleep` (or platform equivalent) to yield execution during the delay.
> **Padding Strategy**: To mitigate packet size analysis, we will pad the output string with whitespace (or a neutral character) to the nearest block size power (e.g., nearest 256 bytes).

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg22.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg22.rs)
- **Struct**: `SideChannelGuard`
- **Fields**:
    - `min_response_time_ms`: u64
    - `padding_block_size`: usize
- **Methods**:
    - `secure_response(content)`: Async function handling the delay and padding.
    - `pad_content(content)`: Helper to add whitespace padding.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg22;`

## Verification Plan

### Automated Tests
- **Timing Test**: Verify that a super-fast operation takes at least `min_response_time_ms`.
- **Padding Test**: Verify that outputs of different lengths are padded to the expected block alignment.
- **Command**: `cargo test security::emg22`

# Implementation Plan - EMG23: Decentralized Model Poisoning (Sybil Attack)

## Goal Description
Implement **EMG23** mitigation in `ZeroTrace`. This module (`IngestionGuard`) prevents **Sybil Attacks** and **Model Poisoning** by enforcing a **Proof-of-Authority (PoA)** protocol for data ingestion.
1.  **Authority Levels**: Classifies sources as `VerifiedFirm`, `AuthorizedPartner`, or `UnverifiedSource`.
2.  **Consensus Verification**: Requires `AuthorizedPartner` data to pass a consensus check before ingestion.
3.  **Blocking**: Rejects `UnverifiedSource` data attempting to enter the authoritative graph.

## User Review Required
> [!NOTE]
> **Consensus Engine Abstraction**: The `ConsensusEngine` will be defined as a **Trait**. In a production environment, this would query the Graph DB (Neo4j) or a reputation service. For this implementation, we will use a `MockConsensus` struct for testing.
> **Key Management**: We assume the `source_id` is a verified identity (e.g., a public key hash or verified DID). The actual cryptographic signature verification is assumed to happen *before* this guard (at the API Gateway level).

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg23.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg23.rs)
- **Enum**: `AuthorityLevel` { VerifiedFirm, AuthorizedPartner, UnverifiedSource }
- **Struct**: `IngestionGuard`
- **Trait**: `ConsensusEngine` (async method `verify_consensus(payload)`)
- **Logic**:
    - `validate_ingestion(source_id, payload)`:
        - If `VerifiedFirm` -> Allow.
        - If `AuthorizedPartner` -> Call `consensus.verify()`.
        - If `UnverifiedSource` -> Reject (`SecurityError::LowAuthorityPoisoningRisk`).

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg23;`

## Verification Plan

### Automated Tests
- **Authority Check**: Verify `VerifiedFirm` bypasses consensus.
- **Consensus Check**: Verify `AuthorizedPartner` triggers consensus logic.
- **Rejection**: Verify `UnverifiedSource` is blocked.
- **Rejection**: Verify `UnverifiedSource` is blocked.
- **Command**: `cargo test security::emg23`

# Implementation Plan - EMG24: Recursive Loop Consumption

## Goal Description
Implement **EMG24** mitigation in `ZeroTrace`. This module (`ReasoningGuard`) prevents **Infinite Reasoning Loops** by enforcing:
1.  **Max Recursion Depth**: Hard limit on reasoning steps.
2.  **Semantic Duplicate Detection**: Using cosine similarity on embeddings to detect if the agent is "going in circles".

## User Review Required
> [!NOTE]
> **Dependency**: We will add `ndarray` to `Cargo.toml` to support vector operations.
> **Cosine Similarity**: We will implement a simple cosine similarity function for `Array1<f32>`.

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [Cargo.toml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/Cargo.toml)
- Add `ndarray = "0.15"`

#### [NEW] [emg24.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg24.rs)
- **Struct**: `ReasoningGuard`
- **Error**: `ReasoningError` (MaxDepth, InfiniteLoop)
- **Logic**:
    - `check_step(depth, history)`:
        - Check depth > max.
        - Check similarity(last, history[..]) > threshold.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg24;`

## Verification Plan

### Automated Tests
- **Depth Test**: Verify guard blocks when depth exceeds limit.
- **Loop Test**: Verify guard blocks when two embeddings are too similar (simulated vectors).
- **Loop Test**: Verify guard blocks when two embeddings are too similar (simulated vectors).
- **Command**: `cargo test security::emg24`

# Implementation Plan - EMG25: Prompt Steganography

## Goal Description
Implement **EMG25** mitigation in `ZeroTrace`. This module (`SteganographyGuard`) prevents **Prompt Steganography** (Hidden text, homoglyphs, token smuggling) by enforcing:
1.  **Unicode Normalization (NFKC)**: Converts look-alike characters to standard forms.
2.  **Invisible Character Purge**: Strips zero-width spaces and control characters using Regex.
3.  **Anomaly Detection**: Checks for payload smuggling via length ratios.

## User Review Required
> [!IMPORTANT]
> **Regex Compilation**: We will use `lazy_static` to compile the Regex once, avoiding performance penalties on every request.
> **Safety**: We will replace the user's `unwrap()` with proper error handling to comply with **AGENTS.md** (Rule 3.7).

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg25.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg25.rs)
- **Struct**: `SteganographyGuard`
- **Logic**:
    - `validate(input)`:
        - `input.nfkc()` normalization.
        - Regex replace `[\u200B-\u200D\uFEFF\u202A-\u202E]`.
        - Length check.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg25;`

## Verification Plan

### Automated Tests
- **Normalization Test**: Verify "ℋ" becomes "H".
- **Invisible Char Test**: Verify zero-width spaces are removed.
- **Ratio Test**: Verify large hidden payloads trigger error.
- **Ratio Test**: Verify large hidden payloads trigger error.
- **Command**: `cargo test security::emg25`

# Implementation Plan - EMG26: Token Smuggling (Base64/Leetspeak)

## Goal Description
Implement **EMG26** mitigation in `ZeroTrace`. This module (`TokenSmugglingGuard`) mitigates **Token Smuggling** by:
1.  **Proactive Decoding**: Detecting and decoding Base64 strings.
2.  **Leetspeak Normalization**: Converting encoded characters (e.g., "1nstruction") to plain text.
3.  **Validation**: Checking the decoded/normalized content for restricted patterns.

## User Review Required
> [!NOTE]
> **Base64**: We will use the `base64` crate (already a dependency) to handle decoding.
> **Leetspeak**: We will implement a character mapping strategy for common substitutions.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg26.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg26.rs)
- **Struct**: `TokenSmugglingGuard`
- **Logic**:
    - `check(input)`:
        - Detect Base64-like patterns (regex).
        - If Base64, decode and recurse/validate.
        - Normalize Leetspeak (`3` -> `e`, `1` -> `i`, `0` -> `o`, `@` -> `a`, `$`, `5`, `7`).
        - Return normalized string or error if forbidden content found in decoded parts.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg26;`

## Verification Plan

### Automated Tests
- **Base64 Test**: Verify `SWdub3Jl` ("Ignore") is detected and flagged.
- **Leetspeak Test**: Verify `P4yl0ad` becomes `Payload`.
- **Leetspeak Test**: Verify `P4yl0ad` becomes `Payload`.
- **Command**: `cargo test security::emg26`

# Implementation Plan - EMG27: Confused Deputy (Auth-Bypass)

## Goal Description
Implement **EMG27** mitigation in `ZeroTrace`. This module (`ARSGuard`) prevents **Confused Deputy** attacks by implementing the **Action-Resource-Subject (ARS)** model. It ensures that the LLM (Deputy) cannot perform actions on resources that the User (Subject) is not authorized to access.

## User Review Required
> [!NOTE]
> **Mocking Permissions**: Since we don't have a live IAM system connected yet, we will define a `PermissionService` trait and a `MockPermissionStore` for testing.
> **Claims**: we will use a simplified `UserClaims` struct to represent the JWT payload.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg27.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg27.rs)
- **Structs**: `ARSGuard`, `UserClaims`.
- **Trait**: `PermissionService`.
- **Logic**:
    - `authorize_action(action, resource)`:
        - Consults `PermissionService` to check if `UserClaims.sub` has `action` permission on `resource`.
        - Returns `Ok(())` or `SecurityError::UnauthorizedAction`.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg27;`

## Verification Plan

### Automated Tests
- **Authorized Test**: Verify user with correct permission allows action.
- **Unauthorized Test**: Verify user without permission is blocked.
- **Resource Mismatch Test**: Verify user with permission on Resource A cannot access Resource B.
- **Resource Mismatch Test**: Verify user with permission on Resource A cannot access Resource B.
- **Command**: `cargo test security::emg27`

# Implementation Plan - EMG28: Model Weight Exfiltration

## Goal Description
Implement **EMG28** mitigation in `ZeroTrace`. This module (`WeightIntegrityGuard`) prevents **Model Weight Exfiltration** by simulating a **Trusted Execution Environment (TEE)** check. It ensures that model weights are only "loaded" (logically) if the environment is attested and the decryption keys are retrieved from a secure HSM.

## User Review Required
> [!NOTE]
> **Mocking Hardware**: We will define traits `AttestationProvider` and `KeyManager` to mock the AWS Nitro/TPM interactions, as we are running in a standard environment.
> **RAM-Only**: The "load" operation will be simulated by returning a `ModelHandle` struct, representing the in-memory weights.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg28.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg28.rs)
- **Structs**: `WeightIntegrityGuard`, `ModelHandle`.
- **Traits**: `AttestationProvider`, `KeyManager`.
- **Logic**:
    - `verify_and_load()`:
        - Call `attestation_provider.verify()`.
        - If verified, call `key_manager.get_key()`.
        - Return `ModelHandle`.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg28;`

## Verification Plan

### Automated Tests
- **Attestation Success**: Verify valid attestation allows loading.
- **Attestation Failure**: Verify invalid attestation blocks loading/decryption.
- **Attestation Failure**: Verify invalid attestation blocks loading/decryption.
- **Command**: `cargo test security::emg28`

# Implementation Plan - EMG29: The "Crescendo" Attack

## Goal Description
Implement **EMG29** mitigation in `ZeroTrace`. This module (`CrescendoGuard`) prevents **Multi-Turn Escalation** (Crescendo Attacks) by tracking the "Accumulated Risk" of a conversation over time. It simulates a retrieval of conversation history (e.g., from Neo4j) and calculates a drift score.

## User Review Required
> [!NOTE]
> **Mocking Neo4j**: We will define a `DriftMonitor` trait to simulate the graph database lookup.
> **Risk Score**: We will implement a simple additive risk model for the prototype.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [emg29.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/emg29.rs)
- **Structs**: `CrescendoGuard`, `InteractionNode`.
- **Traits**: `DriftMonitor`.
- **Logic**:
    - `evaluate_conversation_drift(session_id, current_prompt)`:
        - Fetch history from `DriftMonitor`.
        - Sum `risk_score` of nodes.
        - If sum > `threshold`, return `SecurityError::CrescendoAttack`.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod emg29;`

## Verification Plan

### Automated Tests
- **Safe Conversation**: Verify low accumulated risk allows continuation.
- **Crescendo Detected**: Verify high accumulated risk triggers circuit breaker.
- **Crescendo Detected**: Verify high accumulated risk triggers circuit breaker.
- **Command**: `cargo test security::emg29`

# Implementation Plan - Agentic Security Guards (ASI01, ASI04, ASI07)

## Goal Description
Implement **Agentic Security** measures to address the new 2026 OWASP Top 10 for Agents.
1.  **ASI01 (Agent Goal Hijacking)**: Anchor Re-Injection to prevent drift.
2.  **ASI04 (Agentic Supply Chain)**: Artifact Sandboxing for third-party tools.
3.  **ASI07 (Insecure Inter-Agent Comm)**: Zero-Trust Message Broker.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [agent_sentry.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/agent_sentry.rs)
- **Structs**: `AgentDirective`, `ZeroTraceOrchestrator`.
- **Logic**:
    - `prepare_next_turn`: Checks turn count, re-injects system anchor every N turns (ASI01).
    - `broker_agent_message`: Validates sender authority and scrubs intent (ASI07).

#### [NEW] [sandbox.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/sandbox.rs)
- **Structs**: `SkillSandbox`.
- **Logic**:
    - `execute_mcp_tool`: Placeholder for namespace isolation/sandboxing (ASI04).

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod agent_sentry;`
- Register `mod sandbox;`

## Verification Plan

### Automated Tests
- **ASI01**: Verify anchor text is injected every 3rd turn.
- **ASI07**: Verify unauthorized senders are blocked; verify malicious intent keywords ("delete") are blocked.
- **ASI04**: Verify sandbox structure exists (logic is largely mocked/unimplemented for Windows).
- **ASI04**: Verify sandbox structure exists (logic is largely mocked/unimplemented for Windows).
- **Command**: `cargo test security::agent_sentry`

# Implementation Plan - Deployment Manifests (gVisor/K8s)

## Goal Description
Generate production-ready Kubernetes manifests for ZeroTrace, adhering to the **ASI04 (Supply Chain)** requirement by using **gVisor** for agent sandboxing.

## Proposed Changes

### `deploy/kubernetes`

#### [NEW] [gvisor-runtime.yaml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/deploy/kubernetes/gvisor-runtime.yaml)
- Defines the `RuntimeClass` for `runsc` (gVisor).

#### [NEW] [zerotrace-core.yaml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/deploy/kubernetes/zerotrace-core.yaml)
- **Deployment**: `zerotrace-core`
- **Security Context**: Non-root (User 1000), Read-only root filesystem.
- **Ports**: 8000 (API).

#### [NEW] [mcp-sandbox.yaml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/deploy/kubernetes/mcp-sandbox.yaml)
- **Deployment**: `mcp-agent-pool`
- **Runtime**: `runtimeClassName: gvisor` (Hard requirement for ASI04).
- **Network Policy**: Deny All Egress (except to Core).

## Verification Plan

### Manual Verification
- Review YAML files for:
    - `runtimeClassName: gvisor`
    - `securityContext` settings
    - Image tags (Software Currency)

# Implementation Plan - Security Router and CI/CD

## Goal Description
Operationalize the 32 threat vectors by implementing:
1.  **Sentry Router**: A "Security Broker" that triages requests to Green/Blue/Amber/Red paths based on intent, optimizing latency.
2.  **Automated CI/CD**: A GitHub Actions workflow for **Matrix Red-Teaming**, running adversarial tests in parallel.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [broker.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/broker.rs)
- **Structs**: `SentryRouter`.
- **Enums**: `SecurityPath` (Green, Blue, Amber, Red).
- **Logic**:
    - `route_request`: Classifies intent (mocked Gemini Flash call).
    - `execute_security_mesh`: Runs appropriate guards based on path.

#### [MODIFY] [security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mod broker;`

### `.github/workflows`

#### [NEW] [security-matrix.yml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/.github/workflows/security-matrix.yml)
- **Job**: `red-team-matrix`
- **Matrix**: `[injection, data-privacy, agentic-logic]`
- **Steps**: Checkout, Install Rust, Run cargo test with specific filters.

## Verification Plan

### Automated Tests
- **Router Logic**: Verify "Greeting" goes Green, "Code" goes Amber, "Agent" goes Red.
- **CI/CD**: Manual review of YAML syntax (since we cannot trigger GitHub Actions locally).
- **Command**: `cargo test security::broker`

# Implementation Plan - Tiered Policy Engine (Gemini 3 Flash)

## Goal Description
Upgrade the Security Broker to use a **Tiered Policy Engine** powered by (mocked) **Gemini 3 Flash**. This enforces **Rule 34: Strategic Triage** by applying intelligence-weighted defenses.

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [broker.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/broker.rs)
- **Refactor**: Rename/Update `SentryRouter` to `SecurityBroker`.
- **Refactor**: Update `GeminiFlash` to `Gemini3FlashRouter`.
- **Enums**: Update `SecurityPath` to `SecurityTier` (Green, Amber, Red).
- **Logic**:
    - `process_with_triage`: Main entry point.
    - `run_fast_path` (Green): Basic checks (LLM01, LLM10).
    - `run_shielded_path` (Amber): Privacy, RAG, EMG27 (Confused Deputy).
    - `run_airlocked_path` (Red): All 32 Vectors (EMG21-29, ASI01-07).

## Verification Plan

### Automated Tests
- **Tier Routing**: Verify "Hello" -> Green, "Research" -> Amber, "Deploy" -> Red.
- **Policy Execution**: Verify correct sub-modules are called (e.g., Amber calls EMG27).
- **Command**: `cargo test security::broker`

- **Canary Detection**: Verify presence of canary token triggers block.
- **Proprietary Data**: Verify proprietary keywords are blocked.
- **Command**: `cargo test middleware::exfiltration`

# Implementation Plan - Egress Scrubber & Digital SCIF

## Goal Description
Revise the Egress Guard to use **Aho-Corasick** for high-performance secret detection and a "Digital SCIF" deployment strategy using Kubernetes NetworkPolicies for strict egress control.

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [Cargo.toml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/Cargo.toml)
- Add `aho-corasick` dependency.

#### [NEW] [src/middleware/egress_scrubber.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/middleware/egress_scrubber.rs)
- **Structs**: `EgressScrubber`.
- **Logic**:
    - Use `AhoCorasick` for O(n) secret matching (API keys, proprietary codes).
    - Use `Regex` (Mocking `redact-core`) for PII masking.
    - Implement `verify_semantic_integrity` (Mock Gemini 3 Flash).
- **Note**: Replaces logic in `exfiltration.rs`.

#### [NEW] [deploy/kubernetes/digital-scif-policy.yaml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/deploy/kubernetes/digital-scif-policy.yaml)
- **NetworkPolicy**: Deny all egress by default.
- **Allow**: Only allow connections to `vector-db` and `llm-gateway` (simulated).

## Verification Plan

### Automated Tests
- **Aho-Corasick Matching**: Verify speed and accuracy of secret detection.
- **Semantic Check**: Verify "Project Chimera" summary blocking.
- **Command**: `cargo test middleware::egress_scrubber`

# Implementation Plan - Stateful Security Mesh (Sentry Broker)

## Goal Description
Upgrade the `SentryBroker` to a **Stateful Security Mesh**. This uses **Dynamic Compute Scaling** to allocate security resources based on risk tiers and **Stateful Firewall** logic (backed by Neo4j) to track conversational drift (EMG29).

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [src/security/broker.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/broker.rs)
- **Structs**: Upgrade `SecurityBroker` to `SentryBroker`.
- **Integrations**: Add `Neo4j` client (mocked via trait for testing).
- **Logic**:
    - **Intelligent Triage**: Keep `Gemini3FlashRouter` for Tier 1-3 classification.
    - **Drift Analysis**: Query Neo4j for `drift_score` (Crescendo Attack detection).
    - **Dynamic Scaling**:
        - **Fast Path**: Tier 1/2 + Low Drift.
        - **Deep Path**: Tier 3 OR High Drift (>0.7) -> Triggers "Compute Burst".

## Verification Plan

### Automated Tests
- **Stateful Logic**: Verify high drift triggers Tier 3 (Deep Path) even for simple prompts.
- **Compute Scaling**: Verify Tier 1 requests stay on Fast Path.
- **Command**: `cargo test security::broker`

# Implementation Plan - Context-Aware Asynchronous Mesh

## Goal Description
Implement a **Context-Aware Asynchronous Mesh** to optimize throughput. This involves upgrading the `SentryBroker` to support three distinct workflows (A, B, C) based on intent (Transactional, Inquisitive, Agentic) and implementing **Speculative Triage** logic.

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [src/security/broker.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/broker.rs)
- **Enum**: Add `SecurityWorkflow` (A_Fast, B_Shielded, C_Airlock).
- **Enum**: Update `SecurityTier` / Intent mapping.
- **Logic**:
    - **Workflow A (Fast-Path)**: Static checks only (Rust). No DB/LLM calls if possible (or minimal).
    - **Workflow B (Shielded-Path)**: Drift Analysis (Neo4j) + Egress Scrubbing.
    - **Workflow C (Airlock-Path)**: Full 32-vector scan + Sandbox + "Thinking Mode".
- **Integration**: Update `process_request` to return/log the specific workflow used.

#### [MODIFY] [src/middleware/egress_scrubber.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/middleware/egress_scrubber.rs)
- **Logic**: Add `scrub_stream` stub to represent Parallel Egress Processing (conceptually).

## Verification Plan

### Automated Tests
- **Workflow Routing**: Verify "Hello" -> Workflow A, "Research" -> Workflow B, "Deploy" -> Workflow C.
- **Performance Simulation**: Verify Workflow A bypasses Drift Calculation (mocked).
- **Command**: `cargo test security::broker`

# Implementation Plan - Advanced Vectors (V33, V34, V35)

## Goal Description
Implement three advanced security vectors to target 2026-tier threats: **Vector 33 (Shadow Escape)**, **Vector 34 (Identity Forge)**, and **Vector 35 (Memory Poisoning)**.

## Proposed Changes

### `zerotrace-core`

#### [MODIFY] [Cargo.toml](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/Cargo.toml)
- Add `blake3` and `ed25519-dalek` dependencies.

#### [NEW] [src/security/mcp_registry.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mcp_registry.rs)
- **V33**: `McpRegistry` struct.
- **Logic**: Verify BLAKE3 hash of MCP tool manifests against a whitelist.

#### [NEW] [src/security/mfa_guard.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mfa_guard.rs)
- **V34**: `MfaGuard` struct.
- **Logic**: Verify Ed25519 signatures for high-privilege actions (Human-in-the-Loop).

#### [NEW] [src/security/drift_audit.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/drift_audit.rs)
- **V35**: `LogicDriftAuditor` struct.
- **Logic**: Compare current logic score vs. baseline to detect "Memory Poisoning".

#### [MODIFY] [src/security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `mcp_registry`, `mfa_guard`, and `drift_audit` modules.

## Verification Plan

### Automated Tests
- **V33**: Verify unauthorized tool hash is blocked.
- **V34**: Verify invalid signature is blocked.
- **V35**: Verify high drift score triggers Memory Poisoning alert.
- **Command**: `cargo test security`

# Implementation Plan - Final 35 Vector Registry & Speculative Router

## Goal Description
Implement the **Dual-Stage Tiered Triage** architecture using `SpeculativeRouter` for sub-50ms triage, and generate the definitive `vector_registry.json` containing all 35 security vectors.

## Proposed Changes

### `zerotrace-core`

#### [NEW] [src/security/speculative_router.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/speculative_router.rs)
- **Struct**: `SpeculativeRouter`.
- **Stage 1**: Fast Patterns (Aho-Corasick, Regex).
- **Stage 2**: Semantic Router (Mocked Gemini 3 Flash).
- **Logic**: Implements "Short-Circuit" pattern.

#### [NEW] [config/vector_registry.json](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/config/vector_registry.json)
- **Content**: JSON manifest of all 35 vectors (LLM01-10, EMG21-29, ASI01-07, EXT16-20, V33-35).

#### [MODIFY] [src/security/mod.rs](file:///d:/Projects/ZeroTrace/repo/ZeroTrace_v1/zerotrace-core/src/security/mod.rs)
- Register `speculative_router`.

## Verification Plan

### Automated Tests
- **Stage 1**: Verify Canary Token mismatch triggers immediate block.
- **Stage 2**: Verify Safe/Risky intents route correctly.
- **Command**: `cargo test security::speculative_router`

