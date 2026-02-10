# ZeroTrace Emergency Procedures

## Scenario: Tier 3 Outlier (EMG27 AI Worm)
**Trigger**: Postgres Audit records a Severity 5 event with Risk Code `EMG27`.
**Automated Response**: `ForensicSentinel` executes `neo4j_lockdown.cypher`.

## State: "Amber Stasis"
*   **Graph DB**: Read-Only for everyone except Admin.
*   **Edge Sidecar**: Fails-Closed (blocks all traffic).
*   **Bots**: Suspended.

## Manual Override (The "Break Glass" Protocol)

To lift the lockdown after the threat is neutralized:

1.  **Access the Bastian Host**:
    Connect via SSH to the secure admin terminal.

2.  **Verify Containment**:
    Run `neo4j_queries.cypher` (Query 5) to confirm the infection loop is broken.

3.  **Execute Lift Script**:
    ```cypher
    // LIFT LOCKDOWN
    ALTER USER forensic_bot SET STATUS ACTIVE;
    REVOKE DENY WRITE ON GRAPH zerotrace_forensics FROM PUBLIC;
    REVOKE DENY WRITE ON GRAPH zerotrace_forensics FROM auditor;
    ```

4.  **Re-Verify**:
    Check `FORENSIC_STATUS` in the Dashboard.
