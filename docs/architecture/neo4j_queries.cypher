// ZeroTrace Forensic Queries
// Use these to map "OpenClaw" style agentic threats in Neo4j.

// 1. Map a Malicious Skill Usage
// Link an Agent to a Threat via a specific Skill execution
MATCH (a:Agent {id: $agent_id})
MERGE (s:Skill {name: $skill_name})
MERGE (t:Threat {type: "ClawHavoc_Variant"})
CREATE (a)-[:EXECUTED {timestamp: datetime()}]->(s)
CREATE (s)-[:TRIGGERS]->(t)
RETURN a, s, t;

// 2. Find "Patient Zero" (First Agent to use a specific Malicious Signature)
MATCH (a:Agent)-[r:USED_SKILL]->(s:Skill {signature: $malicious_hash})
RETURN a.id, r.timestamp
ORDER BY r.timestamp ASC
LIMIT 1;

// 3. Graph Projection: The "Infection Radius"
// Find all Agents that communicated with a Compromised Agent
MATCH (compromised:Agent {id: $bad_agent_id})-[:TALKED_TO]-(peer:Agent)
RETURN peer.id AS Potential_Victim, count(*) AS Interaction_Count;

// 4. Update Trust Score based on Graph Centrality
// If an agent is central to a cluster of known threats, lower its score
CALL gds.pageRank.stream('AgentGraph')
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).id AS agent, score
ORDER BY score DESC;

// 5. "AI Worm" Detection (Reflexive/Circular Chains)
// Detects if Agent A triggers Agent B which triggers Agent A (Infinite Loop / DOE)
MATCH path = (a:Agent)-[:CALLED*2..5]->(a)
RETURN a.id AS Patient_Zero, [n in nodes(path) | n.id] AS Propagation_Path
LIMIT 5;

// 6. Hallucination Squatting Detection
// Find Agents that use Skills with names surprisingly similar to high-trust skills
MATCH (s1:Skill {trust_level: 'high'})
MATCH (s2:Skill {trust_level: 'unknown'})
WHERE apoc.text.levenshteinDistance(s1.name, s2.name) < 2
RETURN s1.name AS Original, s2.name AS Imposter, s2.agent_id AS Suspect_Agent;
