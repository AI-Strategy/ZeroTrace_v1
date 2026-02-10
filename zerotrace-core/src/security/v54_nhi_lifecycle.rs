// src/security/v54_nhi_lifecycle.rs
// Vector 54: Runaway Agent Sprawl (Zombie Identities)
// Defense: Identity Kill-Switch. Revokes NHI tokens older than TTL.

use chrono::{DateTime, Utc, Duration};

pub struct NhiToken {
    pub id: String,
    pub last_attested: DateTime<Utc>,
    pub ttl_days: i64,
}

#[derive(Debug, PartialEq)]
pub enum TokenState {
    Active,
    Expired(i64), // Days overdue
}

impl NhiToken {
    pub fn new(id: &str, last_attested: DateTime<Utc>, ttl_days: i64) -> Self {
        Self {
            id: id.to_string(),
            last_attested,
            ttl_days,
        }
    }

    pub fn check_status(&self) -> TokenState {
        let now = Utc::now();
        let age_days = now.signed_duration_since(self.last_attested).num_days();

        if age_days > self.ttl_days {
            TokenState::Expired(age_days - self.ttl_days)
        } else {
            TokenState::Active
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zombie_detection() {
        let now = Utc::now();
        let two_months_ago = now - Duration::days(60);
        
        let zombie_token = NhiToken::new("agent-007", two_months_ago, 30);
        
        match zombie_token.check_status() {
            TokenState::Expired(overdue) => assert!(overdue >= 29), // approx 30 days overdue
            _ => panic!("Should be expired"),
        }
    }

    #[test]
    fn test_active_token() {
        let now = Utc::now();
        let yesterday = now - Duration::days(1);
        
        let active_token = NhiToken::new("agent-008", yesterday, 30);
        assert_eq!(active_token.check_status(), TokenState::Active);
    }
}
