# ZeroTrace Graph Isolation Strategy

## The Threat: Lateral Movement via Graph
If an attacker compromises the Graph Database, they can theoretically "traverse" from a low-value node (e.g., a public skill) to a high-value node (e.g., a user's session) to learn behaviors.

## The Defense: "Digital SCIF" Segmentation

### 1. The "Air Gap" Property
We use **Label-Based Access Control (LBAC)** to create invisible walls within the graph.
*   **Public Zone**: `(:Agent)`, `(:Skill)`, `(:Resource)`
*   **Private Zone**: `(:User)`, `(:Session)`
*   **Restricted Zone**: `(:PiiNode)`, `(:Secret)`

### 2. The "Blind" Forensic Bot
The Rust Sentinel (`forensic_bot`) is granted **Write-Only** access to specific pathways.
*   It can insert: `(User)-[:CALLED]->(Agent)`
*   It *cannot* query: `MATCH (u:User) RETURN u.pii` (Denied by Metadata Policy).

### 3. Break-Glass Procedure
For deep investigations (e.g., finding the "Patient Zero" of a Worm), an Admin must:
1.  Login via MFA-protected console.
2.  Assume the `root` role temporarily.
3.  Run the specific forensic query.
4.  Session is logged in Postgres Audit with `intervention_type: 'BREAK_GLASS'`.
