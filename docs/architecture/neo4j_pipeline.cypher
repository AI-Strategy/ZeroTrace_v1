// ZeroTrace Postgres -> Neo4j ETL Pipeline
// Maps flat audit logs to a rich Forensic Graph for "AI Worm" detection.

// 1. Ingest User Nodes
// UNWIND batch of Postgres logs
MERGE (u:User {id: $user_id})
ON CREATE SET u.first_seen = datetime($timestamp), u.risk_score = 0.0
ON MATCH SET u.last_seen = datetime($timestamp);

// 2. Ingest Session Nodes
MERGE (s:Session {id: $session_id})
ON CREATE SET s.timestamp = datetime($timestamp)
MERGE (u)-[:INITIATED]->(s);

// 3. Ingest Agent/Tool Nodes (The "Vector")
// If the log contains an Agent ID
WITH u, s
WHERE $agent_id IS NOT NULL
MERGE (a:Agent {id: $agent_id})
ON CREATE SET a.reputation = 0.5 -- Neutral start
MERGE (s)-[:CALLED_AGENT]->(a);

// 4. Map Infection Paths (The "Trace")
// If metadata contains "upstream_agent_id", link them
WITH a
WHERE $metadata.upstream_agent_id IS NOT NULL
MERGE (upstream:Agent {id: $metadata.upstream_agent_id})
CREATE (upstream)-[:TRIGGERED {timestamp: datetime($timestamp)}]->(a);

// 5. Flag "Patient Zero" Candidates
// If Risk Code is EMG27 (Worm), mark the Agent
WITH a
WHERE $risk_code = 'EMG27'
SET a:Compromised, a.risk_level = 'CRITICAL'
CREATE (a)-[:EXHIBITED_BEHAVIOR]->(r:Risk {code: 'EMG27', severity: 5});
