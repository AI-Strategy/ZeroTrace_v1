// V39: Toxic Combination Guard
// Detects when an agent uses two "innocent" tools that, when combined, create a high-risk capability.

// 1. Tag Agents with High-Risk Combinations
MATCH (a:Agent)-[:USED_TOOL]->(t1:Tool)
MATCH (a)-[:USED_TOOL]->(t2:Tool)
WHERE t1.id <> t2.id
  AND (t1.risk_score + t2.risk_score) < 5.0 // Individually safe
  AND exists((t1)-[:TOXIC_WITH]->(t2))       // But defined as toxic pair
MERGE (a)-[:TRIGGERED_VECTOR {vector_id: "V39", severity: "CRITICAL"}]->(t1)
RETURN a.id, t1.id, t2.id;

// 2. Identify Logic Drift (Vector 35)
// Compare current trajectory against Golden Baseline
MATCH (s:Session)-[:NEXT_STEP]->(n:ReasoningNode)
MATCH (baseline:GoldenTrace)-[:NEXT_STEP]->(b:ReasoningNode)
WHERE s.topic = baseline.topic
  AND n.embedding IS NOT NULL
  AND b.embedding IS NOT NULL
  AND gds.similarity.cosine(n.embedding, b.embedding) < 0.75
SET s.drift_alert = true
RETURN s.id, n.content;

// 3. Airlock Trigger (Global Kill-Switch)
// If more than 5 V39 triggers occur in 1 minute, lock the organization.
MATCH (e:Event {vector_id: "V39"})
WHERE e.timestamp > datetime() - duration({minutes: 1})
WITH count(e) as threat_count
WHERE threat_count > 5
MERGE (global:SystemStatus {id: "ZERO_TRACE"})
SET global.status = "AIRLOCK_MODE";
