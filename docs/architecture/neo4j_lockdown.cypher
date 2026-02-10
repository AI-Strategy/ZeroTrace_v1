// ZeroTrace Emergency Lockdown Procedure (Tier 3 Outlier Response)
// EXECUTE ON SYSTEM DATABASE
// Triggered automatically by ForensicSentinel when EMG27 (Ai Worm) Severity 5 is confirmed.

// 1. Immediate Suspension of Active Agents
// Stops all automated read/write patterns to prevent viral spread.
// "Pulling the plug" on the API users.
ALTER USER forensic_bot SET STATUS SUSPENDED;

// 2. Global Write Freeze ("Amber Stasis")
// Prevents any role (except Admin) from modifying the forensic evidence.
// This preserves the "crime scene" state for immutable auditing.
DENY WRITE ON GRAPH zerotrace_forensics TO PUBLIC;
DENY WRITE ON GRAPH zerotrace_forensics TO auditor;

// 3. Quarantine the Affected Cluster (Graph Partitioning)
// If specific Agent IDs are known to be infected ($infected_agents list)
// We theoretically apply a DENY TRAVERSE, but globally suspending the bot is safer/faster.

// 4. Elevate Forensic Admin
// Ensure the cleanup crew has unfettered access during the lockdown.
GRANT ALL ON GRAPH zerotrace_forensics TO forensic_admin;

// 5. Log the Lockdown Event
// (This is usually done in Postgres, but checking system status here)
SHOW USERS WHERE status = 'SUSPENDED';
