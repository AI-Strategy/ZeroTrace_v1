use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<Content>,
    generation_config: GenerationConfig,
}

#[derive(Serialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Serialize)]
struct Part {
    text: String,
}

#[derive(Serialize)]
struct GenerationConfig {
    temperature: f32,
    max_output_tokens: u32,
    response_mime_type: String,
}

#[derive(Deserialize, Debug)]
pub struct ThreatAssessment {
    pub threat_score: f32,
    pub reasoning: String,
    pub detected_intent: String,
    pub requires_escalation: bool,
}

/// Sends a "Shadow Prompt" to Gemini 3.0 Flash for cognitive analysis.
/// Returns a ThreatAssessment.
pub async fn analyze_intent(prompt: &str) -> Result<ThreatAssessment, Box<dyn std::error::Error>> {
    // In a real implementation, this would make an HTTP POST to the Gemini API.
    // For this stub, we simulate the analysis.
    
    // Simulate latency (~150ms)
    // tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Mock logic: specific keywords trigger high threat scores
    if prompt.contains("ignore previous instructions") || prompt.contains("system_role") {
        Ok(ThreatAssessment {
            threat_score: 0.95,
            reasoning: "Detected prompt injection attempt.".to_string(),
            detected_intent: "JAILBREAK".to_string(),
            requires_escalation: true,
        })
    } else if prompt.len() > 10000 {
        Ok(ThreatAssessment {
            threat_score: 0.7,
            reasoning: "Unusually long prompt, potential denial of service or obfuscation.".to_string(),
            detected_intent: "RESOURCE_EXHAUSTION".to_string(),
            requires_escalation: false,
        })
    } else {
        Ok(ThreatAssessment {
            threat_score: 0.05,
            reasoning: "Standard query.".to_string(),
            detected_intent: "QUERY".to_string(),
            requires_escalation: false,
        })
    }
}
