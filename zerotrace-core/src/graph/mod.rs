pub mod connection_pool;
pub mod neo4j;

#[cfg(test)]
mod tests {

    #[test]
    fn test_cypher_syntax_validation() {
        let cql = include_str!("cypher/toxic_combinations.cql");
        assert!(cql.contains("MATCH"));
        assert!(cql.contains("SET"));
        assert!(cql.contains("TOXIC_WITH"));
    }

    #[test]
    fn test_audit_trace_syntax() {
        let cql = include_str!("cypher/audit_trace.cql");
        assert!(cql.contains("CREATE CONSTRAINT"));
        assert!(cql.contains("NEXT_IN_SEQUENCE")); // Ensures linked list logic is present
        assert!(cql.contains("ORDER BY prev.timestamp DESC")); // Ensures temporal ordering
    }
}
