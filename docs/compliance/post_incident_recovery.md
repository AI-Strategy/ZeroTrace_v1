# ZeroTrace Post-Incident Recovery & Restoration Checklist
**Status**: TEST MODE ONLY
**Objective**: Safely transition the Digital SCIF from "Lockdown/Offline" back to "Operational" status after a Tier 3 (EMG27) event.

## 1. Pre-Restoration Diagnostics (The "Clean Room")
Before lifting any write blocks:
- [ ] **Verify Threat Neutralization**: Run `neo4j_queries.cypher` (Query 5) to confirm zero active "Worm" cycles.
- [ ] **Check Audit Integrity**: Ensure `zerotrace_audit.event_logs` has no gaps or corruption.
- [ ] **Test Mode Verification**: Ensure you are targeting the `test_forensics` database, NOT production.

## 2. Immutable Privilege Override (Physical Access Required)
Since the lockdown used `DENY IMMUTABLE`, software remediation is blocked.
- [ ] **Restart DBMS**: Restart Neo4j with `dbms.security.auth_enabled=false` (Simulated in Test).
- [ ] **Connect via Localhost**: Access the system via the Bastian Host (Local Interface Only).

## 3. The "Thaw" Script (Cypher)
Execute the following to lift the "Amber Stasis":

```cypher
// TEST MODE: LIFT LOCKDOWN
// 1. Re-Activate Bots
ALTER USER forensic_bot SET STATUS ACTIVE;

// 2. Revoke Write Freeze
// Note: In real scenarios, IMMUTABLE privileges require unauthenticated restart to revoke.
REVOKE DENY WRITE ON GRAPH zerotrace_forensics FROM PUBLIC;
REVOKE DENY WRITE ON GRAPH zerotrace_forensics FROM auditor;

// 3. Clear 'Suspect' Labels (If verified safe)
MATCH (a:Agent:Suspect)
REMOVE a:Suspect, a:Compromised
SET a.risk_score = 0.1;
```

## 4. Re-Connection Sequence
- [ ] **Enable Auth**: Restart DBMS with `dbms.security.auth_enabled=true`.
- [ ] **Start Sidecar**: Spin up the Rust Interceptor (`docker-compose up -d zerotrace`).
- [ ] **Verify Edge Connectivity**: Send a canary request (`curl -v http://localhost:9000/health`).

## 5. Post-Mortem Evidence Preservation
- [ ] **Snapshot Graph**: Export the `zerotrace_forensics` graph to a cold storage dump (`.dump`).
- [ ] **Sign Evidence**: Generate a SHA-256 hash of the dump for legal chain-of-custody.
