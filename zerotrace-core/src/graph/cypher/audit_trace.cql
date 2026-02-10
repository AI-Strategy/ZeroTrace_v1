// zerotrace-core/src/graph/cypher/audit_trace.cql
// Schema Definition for Temporal Sequence Audit (v1.0.3)

// 1. Identity Isolation Constraints
// Ensures that NHI tokens are globally unique across the shard.
CREATE CONSTRAINT nhi_id_unique IF NOT EXISTS FOR (a:Agent) REQUIRE a.nhi_token IS UNIQUE;
CREATE CONSTRAINT org_id_unique IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;

// 2. Trace Node Uniqueness
// Each action block/allow event has a cryptographic UUID.
CREATE CONSTRAINT trace_id_unique IF NOT EXISTS FOR (t:Trace) REQUIRE t.id IS UNIQUE;

// 3. The Temporal Audit Trace Pattern
// This query creates a linked list of events for a specific agent.
// It allows for O(1) retrieval of the "Latest State" and O(k) traversal of history.

// PARAMETERS: $org_id, $nhi_token, $vector_id, $intent_score, $result

// Step A: Ensure Organization and Agent Existence
MERGE (o:Organization {id: $org_id})
MERGE (a:Agent {nhi_token: $nhi_token})
MERGE (o)-[:GOVERNS]->(a)

// Step B: Create the new Trace Node
CREATE (t:Trace {
    id: apoc.create.uuid(),
    timestamp: datetime(),
    vector_id: $vector_id,
    intent_score: $intent_score,
    result: $result
})

// Step C: Link Agent to the Trace and the Vector Definition
WITH t, a
MATCH (v:Vector {id: $vector_id})
CREATE (a)-[:INITIATED]->(t)
CREATE (t)-[:TRIPPED]->(v)

// Step D: Link to Previous Trace (Temporal Chain)
// This logic finds the most recent previous trace for this agent and links it.
WITH t, a
MATCH (a)-[:INITIATED]->(prev:Trace)
WHERE prev <> t
WITH t, prev ORDER BY prev.timestamp DESC LIMIT 1
CREATE (prev)-[:NEXT_IN_SEQUENCE]->(t)
