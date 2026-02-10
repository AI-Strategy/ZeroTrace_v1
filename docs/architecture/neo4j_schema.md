# ZeroTrace Graph Schema

The "Trace" is represented as a series of connected nodes in a Neo4j graph database.

## Node Types

- **User**: Represents an authenticated user of the system.
- **Session**: Represents a user session or interaction context.
- **TraceNode**: Represents a specific interaction or event within a session.
- **DocumentChunk**: Represents a piece of retrieved information or context from the knowledge base (Talos).
- **Canary**: Represents a tracking token injected into a session to detect exfiltration.
- **ShadowPrompt**: A sanitized copy of the user's prompt sent to Gemini 3.0 Flash for logic analysis.
- **ThreatAssessment**: The security scoring and intent analysis returned by Gemini 3.0 Flash.
- **Agent**: Represents an automated agent or MCP client.
- **Skill**: Represents a specific capability or tool used by an agent.
- **DeepResearchTask**: Represents an asynchronous heavy-compute analysis of a novel threat.

## Relationships

- `(:User)-[:INITIATED]->(:Session)`
- `(:Session)-[:TRIGGERED]->(:TraceNode)`
- `(:TraceNode)-[:ACCESSED]->(:DocumentChunk)`
- `(:Session)-[:INJECTED]->(:Canary)`
- `(:TraceNode)-[:TRIGGERED_ALERT]->(:Canary)`
- `(:TraceNode)-[:ANALYZED_AS]->(:ShadowPrompt)`
- `(:ShadowPrompt)-[:SCORED_BY]->(:ThreatAssessment)`
- `(:Agent)-[:USED_SKILL]->(:Skill)`
- `(:Skill)-[:HAS_MANIFEST_SCORE]->(:ThreatAssessment)`
- `(:ThreatAssessment)-[:ESCALATED_TO]->(:DeepResearchTask)`
- `(:DeepResearchTask)-[:YIELDED_RULE]->(:ImmunityRule)`

## Example Query: Cognitive Audit

```cypher
MATCH (s:Session)-[:TRIGGERED]->(t:TraceNode)-[:ANALYZED_AS]->(sp:ShadowPrompt)-[:SCORED_BY]->(ta:ThreatAssessment)
WHERE ta.threat_score > 0.8
RETURN s.id, ta.reasoning, ta.threat_score
```

## Security Auditing

This graph allows us to trace not just *what* data was accessed, but *why* the access was flagged, correlating the deterministic Rust intercepts with the probabilistic Gemini risk scores.
