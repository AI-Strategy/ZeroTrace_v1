# ZeroTrace Threat Intelligence Dashboard

**Goal:** Vizualize real-time threat interception and the "Global Intelligence" feed.

## Layout

### Header
- **Status:** System Online (Green) | Latency: 4ms
- **Global Threat Level:** LOW / ELEVATED / CRITICAL
- **Active Immunizations:** 14,203 Rules

### Main Panel: The Interceptor Live Feed
*Streaming log of blocked attempts.*

| Timestamp | Source IP | Threat Type | Engine | Action | Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 14:02:11 | 192.168.x.x | PII Leak (SSN) | Rust (Aho-Corasick) | **BLOCK** | 1.0 |
| 14:02:15 | 10.0.0.5 | Prompt Injection | Gemini 3 Flash | **FLAG** | 0.95 |
| 14:02:22 | 84.12.x.x | Typosquat (g00gle) | Rust (Levenshtein) | **BLOCK** | 1.0 |

### Sidebar: Deep Research Queue (Tier 3)
*Asynchronous analysis of novel threats.*

- **[Analyzing]** Anomaly #ZT-9942: Recursive base64 encoding pattern.
    - *Status:* Deep Research in progress...
    - *ETA:* 2m 30s

### Footer: Global Graph Connectivity
- **Connected Nodes:** 42 Enterprise Clients
- **Shared Signals:** 1,204 threats shared in last 24h.

## Interactions

- **Click on "FLAG"**: Opens the "Shadow Prompt" view showing the User input vs. Gemini's analysis.
- **Click on "Deep Research"**: Shows the search path and sources (Dark Web/Dev Forums) being queried by the Immunizer.
