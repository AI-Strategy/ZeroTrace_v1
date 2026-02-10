use uuid::Uuid;

/// Generates a new Canary Token.
pub fn generate_canary() -> String {
    format!("ZT-CANARY-{}", Uuid::new_v4())
}

/// Checks if any knwon canary tokens are present in the output.
/// In a real system, this would check against a database of active canaries.
pub fn check_for_exfiltration(content: &str, active_canaries: &[String]) -> Vec<String> {
    let mut detected = Vec::new();
    for canary in active_canaries {
        if content.contains(canary) {
            detected.push(canary.clone());
        }
    }
    detected
}
