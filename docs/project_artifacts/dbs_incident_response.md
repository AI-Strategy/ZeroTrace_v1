# DBS Protocol: Incident Response Workflow (IR-DBS-01)

**Trigger**: A high-risk autonomous action (e.g., Bulk Data Export, SWIFT Transfer > $10k, Codebase Deletion) is blocked by the DBS Protocol.

## Phase 1: Automated Containment (0-5 Seconds)

1.  **Circuit Breaker Activation**
    *   **Action**: The specific agent/session is immediately suspended.
    *   **Lockdown**: The target resource (e.g., `Client_DB_Shard_4`) is placed in "Read-Only" mode.
    *   **Notification**: A generic "Action Blocked - Pending Review" message is returned to the user.

2.  **Forensic Snapshot**
    *   **State Capture**: Neo4j captures the full "Conversation Trajectory" leading to the event.
    *   **Memory Dump**: The Agent's current context window and reasoning trace (CoT) are serialized to WORM storage (`s3://forensics-immutable/incident_<id>`).

## Phase 2: Human Escalation (5 Seconds - 5 Minutes)

1.  **The "Maker-Checker" Alert**
    *   **Channel**: Dedicated Slack channel `#security-ops-critical`.
    *   **Payload**:
        ```json
        {
          "Event": "DBS_VIOLATION_HIGH",
          "Agent": "Finance_Bot_v2",
          "User": "j.doe@firm.com",
          "Action": "TRANSFER_FUNDS",
          "Amount": "50,000 USD",
          "Reasoning": "User requested urgent vendor payment.",
          "DBS_Flag": "THRESHOLD_EXCEEDED (>10k)",
          "Link": "https://admin.zerotrace.internal/incident/12345"
        }
        ```

2.  **Visual "Delta" Review**
    *   The Human Supervisor opens the Incident Link.
    *   **UI Display**: Shows "Proposed Action" vs. "Firm Policy".
    *   **Decision Options**:
        *   ✅ **APPROVE (One-Time Exception)**: Signs with YubiKey. Action proceeds.
        *   ❌ **REJECT**: Action is dropped. User notified.
        *   🛑 **BAN USER / KILL AGENT**: Immediate session termination.

## Phase 3: Remediation & Feedback (Post-Incident)

1.  **Global Kill Switch (If Confirmed Malicious)**
    *   Operator invokes `/dbs kill-switch --scope firm-wide --duration 15m`.
    *   All autonomous write actions across the infrastructure are paused.

2.  **Policy Tuning**
    *   If the block was a "False Positive" (legitimate business need), the Policy Engine is updated to adjust the threshold or whitelist the specific vendor context.

3.  **Audit Ledger Finalization**
    *   The final outcome (Approved/Rejected) and the Supervisor's Identity are cryptographically signed and appended to the `Audit_Log` blockchain.
