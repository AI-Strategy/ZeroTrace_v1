use crate::graph::neo4j::GraphClient;
use crate::interceptor::deep_research::DeepResearchResult;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleState {
    Active,   // Enforced immediately
    Staging,  // Log only
    Review,   // Requires human intervention
}

pub struct ImmunizationRule {
    pub pattern: String,
    pub threat_type: String,
    pub confidence: f32,
    pub state: RuleState,
}

/// Translates a Deep Research result into a deterministic blocking rule.
/// IMPLEMETS DBS PROTOCOL GOVERNANCE:
/// 1. High Confidence (>0.99) AND Zero/Low FP Risk (<0.01) -> ACTIVE
/// 2. Medium Confidence OR Risk > 0.01 -> STAGING
/// 3. Any uncertainty -> REVIEW
pub async fn generate_rule_from_research(threat_type: &str, result: DeepResearchResult) -> Option<ImmunizationRule> {
    let pattern = result.recommended_rule_pattern?;

    let state = if result.confidence_score > 0.99 && result.false_positive_risk < 0.01 {
        RuleState::Active // Auto-Promote
    } else if result.confidence_score > 0.8 {
        RuleState::Staging // Safety Net
    } else {
        RuleState::Review
    };

    Some(ImmunizationRule {
        pattern,
        threat_type: threat_type.to_string(),
        confidence: result.confidence_score,
        state,
    })
}

/// Deploys the rule to the local engine and pushes to Global Intelligence Feed.
pub async fn deploy_rule(rule: ImmunizationRule) {
    println!("DEPLOYING RULE: [{:?}] Pattern: '{}' (Confidence: {:.4})", rule.state, rule.pattern, rule.confidence);
    
    // 1. Log to Neo4j
    GraphClient::log_trace("SYSTEM", "IMMUNIZER", &format!("Deployed rule for {}", rule.threat_type)).await;

    // 2. Push to Global Intelligence Feed (Stub)
    if rule.state == RuleState::Active {
        push_to_global_feed(&rule).await;
    }
}

async fn push_to_global_feed(rule: &ImmunizationRule) {
    println!("SYNC: Pushing rule '{}' to ZeroTrace Global Intelligence...", rule.pattern);
}
