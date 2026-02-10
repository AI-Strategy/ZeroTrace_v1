# AGENTS.md - Governance & Operational Protocol

**Project**: ZeroTrace (AI Security Middleware)
**Stack**: Rust (WASM), Cloudflare Workers, Postgres (Hyperdrive), Neo4j (Aura), Python (Logic/Orchestration).
**Directives Source**: [AI-Strategy/agents.md](https://github.com/AI-Strategy/agents.md) v1.5.0

---

## 1. PROJECT OVERVIEW
ZeroTrace is a "Bulletproof" AI Security Middleware designed to mitigate the **29 Critical AI Risks** (OWASP 2026, MIT Risk Repo). It acts as a hyper-fast sidecar to intercept, audit, and sanitize all AI traffic.

## 2. TECH STACK (STRICT)
*   **Core**: Rust (`worker-rs`), WebAssembly (`wasm32-unknown-unknown`).
*   **Edge**: Cloudflare Workers.
*   **State**: Upstash Redis (Rate Limiting, PII Vault), Postgres (Audit Logs).
*   **Forensics**: Neo4j (Graph Database).
*   **Utilities**: Rust Native (CLI, Axum, Tokio). **NO PYTHON allowed for backend logic.**

---

## 3. GLOBAL DIRECTIVES (MANDATORY)

### 3.1 SOFTWARE CURRENCY & VERIFICATION
*   **Trust No Training Data**: Always verify version numbers via Web Search.
*   **Latest Stable**: Use the latest stable releases for Rust crates and Node packages.
*   **RUST ONLY**: The backend must be 100% Rust. Python is strictly forbidden unless explicitly authorized by the User.

### 3.2 DATA PERSISTENCE
*   **No SQLite**: SQLite is BANNED. Use Postgres or Redis.

### 3.3 DOCUMENTATION AUTHORITY
*   **Source of Truth**: Rely on `/docs` and official documentation, not 3rd-party tutorials.

### 3.4 SECURITY & SECRETS
*   **Zero-Leak**: Secrets in `.env` only.
*   **Hardcoding**: STRICTLY PROHIBITED.

### 3.5 ARCHITECTURAL STANDARDS
*   **Zero Trust**: Authenticate every request.
*   **Fail-Closed**: If a security check fails or errors, BLOCK the request.

### 3.6 LOGGING & OBSERVABILITY
*   **Structured**: JSON logs only.
*   **Immutable**: Audit logs must be tamper-proof (Postgres `security_ledger`).

### 3.7 CODE QUALITY
*   **Strict Typing**: Rust's type system is your friend. No `unwrap()` in production code (use `?` or `expect`).
*   **Tests**: Unit tests required for all security modules.

### 3.8 RESOURCE SAFETY
*   **Token Hygiene**: Monitor for recursive loops (Crescendo/Worms).
*   **Timeouts**: Hard timeouts on all external API calls (Gemini, Redis, Neo4j).

### 3.9 DEFENSIVE POSTURE (PARANOIA)
*   **Input Handling**: Sanitize EVERYTHING. (Unicode Normalization, PII Scrubbing).
*   **Assumption**: The user is an adversary until proven otherwise.

### 3.10 COMPLEX PARSING & REGEX
*   **Regex Discipline**: Use Regex for PII patterns, but Aho-Corasick for high-speed signature matching.
*   **Parsing**: Use parsers (e.g., `serde_json`), not Regex, for structured data.

### 3.11 RATIONALE & CONTEXT
*   **Explain Why**: All complex logic must be documented with *why* it exists, citing specific risk vectors (e.g., LLM01) or business requirements.
*   **Location**: Use inline comments for code-level decisions and `*.md` files (like `implementation_plan.md`) for architectural decisions.
*   **Traceability**: Link code to requirements (e.g., `// See LLM04`).

---

## 4. BOUNDARIES & SAFEGUARDS
*   **Restricted Files**: `.env`, `wrangler.toml` (secrets), `Cargo.lock` (unless updating deps).
*   **Restricted Operations**: `DROP TABLE`, `DELETE GRAPH`, `FLUSHALL` (Redis).
*   **Code Style**: `cargo fmt` and `cargo clippy` MUST pass before commit.
