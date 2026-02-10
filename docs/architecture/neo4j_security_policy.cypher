// ZeroTrace Neo4j Security Policy (RBAC)
// Defines the "Digital SCIF" access controls within the Graph Database.

// 1. Create Roles
CREATE ROLE toxic_cleaner IF NOT EXISTS; -- Can delete toxic nodes
CREATE ROLE forensic_bot IF NOT EXISTS; -- Can write to the graph (The Rust Sentinel)
CREATE ROLE auditor IF NOT EXISTS; -- Can read, but blinded to secrets

// 2. Privilege: Forensic Bot (The Rust Sentinel)
// Allowed to Create/Merge nodes, but cannot read sensitive PII properties
GRANT WRITE ON GRAPH zerotrace_forensics TO forensic_bot;
GRANT READ ON GRAPH zerotrace_forensics TO forensic_bot;
DENY READ {pii_content, secret_key} ON GRAPH zerotrace_forensics TO forensic_bot;

// 3. Privilege: Auditor (Human Compliance Officer)
// Can traverse the graph to see relationships, but cannot see payload content.
GRANT READ ON GRAPH zerotrace_forensics TO auditor;
DENY READ {input_prompt, output_response} ON GRAPH zerotrace_forensics TO auditor;

// 4. Label-Based Isolation (The "SCIF" Walls)
// 'Secret' nodes are only visible to Admin
DENY MATCH (*) ON GRAPH zerotrace_forensics NODES Secret TO auditor;
DENY MATCH (*) ON GRAPH zerotrace_forensics NODES Secret TO forensic_bot;

// 5. Traversal Quotas (DoS Protection)
// call dbms.setQueryMemoryLimit('auditor', '2GB');
// call dbms.setTransactionMemoryLimit('forensic_bot', '512MB');
