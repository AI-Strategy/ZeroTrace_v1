use metrics::{counter, gauge, histogram};

/// Records telemetry for the Shadow Dashboard.
/// 
/// # Arguments
/// * `org_id` - The tenant ID.
/// * `vector_id` - The vector being mitigated (e.g., "V43", "V54").
/// * `score` - The severity score or latency value.
pub fn record_mesh_telemetry(org_id: &str, vector_id: &str, score: f64) {
    // 1. Counter for total blocks per tenant
    // Tracks the "Heatmap" of active threats.
    counter!("zerotrace_mitigation_total", 
             1, // No implicit increment
             "org" => org_id.to_string(), 
             "vector" => vector_id.to_string());

    // 2. Gauge for real-time Reasoning Stability (ASI)
    // Used for the "Identity Kill-Switch" (Panel B).
    // A low score (< 0.25) indicates a Zombie Identity or compromised agent.
    gauge!("zerotrace_agent_stability_index", 
           score,
           "org" => org_id.to_string());

    // 3. Histogram for Speculative Race Latency
    // Monitoring the "One-Way Mirror" performance (Panel C).
    histogram!("zerotrace_mesh_latency_ms", 
               score,
               "org" => org_id.to_string());
}
