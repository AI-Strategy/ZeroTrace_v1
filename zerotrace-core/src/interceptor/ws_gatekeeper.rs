/// V55 WebSocket Hijacking Defense (CVE-2026-25253 Prevention)
///
/// Ensures that WebSocket connection requests (via `gatewayUrl`) originate
/// from a trusted domain in the Neo4j Golden Registry.
pub fn authorize_gateway_connection(requested_url: &str, allowed_gateways: &[String]) -> bool {
    // V55 Defense: Block automatic 'gatewayUrl' parameter hijacking (empty/null check)
    if requested_url.is_empty() { return false; }

    // Strict Origin Enforcement:
    // Only allow if the requested URL starts with a trusted gateway prefix.
    // This prevents attackers from injecting their own listener URL.
    allowed_gateways.iter().any(|trusted| requested_url.starts_with(trusted))
}
