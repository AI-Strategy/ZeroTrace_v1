use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Unauthorized action: Subject {subject} cannot perform {action} on {resource}")]
    UnauthorizedAction {
        subject: String,
        action: String,
        resource: String,
    },
    #[error("Permission check failed: {0}")]
    SystemError(String),
}

/// Simplified representation of JWT claims for the purpose of this guard.
#[derive(Debug, Clone)]
pub struct UserClaims {
    pub sub: String, // Subject (User ID)
    pub role: String, // Role (e.g., "Associate", "Partner")
}

/// Trait to decouple the guard from the actual IAM/Database.
/// In production, this would query a database or valid a partial permission set.
#[async_trait::async_trait]
pub trait PermissionService: Send + Sync {
    async fn check_permission(&self, subject: &str, action: &str, resource: &str) -> bool;
}

pub struct ARSGuard<P: PermissionService> {
    claims: UserClaims,
    permission_service: P,
}

impl<P: PermissionService> ARSGuard<P> {
    pub fn new(claims: UserClaims, permission_service: P) -> Self {
        Self {
            claims,
            permission_service,
        }
    }

    /// Authorize an action using the Action-Resource-Subject (ARS) model.
    /// This prevents the "Confused Deputy" problem by ensuring the *User* has rights,
    /// not just the Agent/Service Account.
    pub async fn authorize_action(&self, action: &str, resource: &str) -> Result<(), AuthError> {
        let allowed = self.permission_service
            .check_permission(&self.claims.sub, action, resource)
            .await;

        if !allowed {
            return Err(AuthError::UnauthorizedAction {
                subject: self.claims.sub.clone(),
                action: action.to_string(),
                resource: resource.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct MockPermissionStore {
        // "Generic" permissions formatted as "subject:action:resource"
        allowed: Mutex<HashSet<String>>,
    }

    impl MockPermissionStore {
        fn new() -> Self {
            Self {
                allowed: Mutex::new(HashSet::new()),
            }
        }
        
        fn grant(&self, subject: &str, action: &str, resource: &str) {
            let key = format!("{}:{}:{}", subject, action, resource);
            self.allowed.lock().unwrap().insert(key);
        }
    }

    #[async_trait::async_trait]
    impl PermissionService for MockPermissionStore {
        async fn check_permission(&self, subject: &str, action: &str, resource: &str) -> bool {
            let key = format!("{}:{}:{}", subject, action, resource);
            self.allowed.lock().unwrap().contains(&key)
        }
    }

    #[tokio::test]
    async fn test_authorized_action() {
        let store = MockPermissionStore::new();
        store.grant("user123", "READ", "case_001.pdf");
        
        let claims = UserClaims { sub: "user123".to_string(), role: "Associate".to_string() };
        let guard = ARSGuard::new(claims, store);

        assert!(guard.authorize_action("READ", "case_001.pdf").await.is_ok());
    }

    #[tokio::test]
    async fn test_unauthorized_action_confused_deputy() {
        let store = MockPermissionStore::new();
        store.grant("user123", "READ", "case_001.pdf");
        // User has NO rights to "case_999_secret.pdf"
        
        let claims = UserClaims { sub: "user123".to_string(), role: "Associate".to_string() };
        let guard = ARSGuard::new(claims, store);

        // The Agent might be able to read it technically, but the Guard MUST block it 
        // because the *Subject* (user123) lacks permission.
        let result = guard.authorize_action("READ", "case_999_secret.pdf").await;
        
        assert!(matches!(result, Err(AuthError::UnauthorizedAction { .. })));
    }

    #[tokio::test]
    async fn test_wrong_action() {
        let store = MockPermissionStore::new();
        store.grant("user123", "READ", "case_001.pdf");
        
        let claims = UserClaims { sub: "user123".to_string(), role: "Associate".to_string() };
        let guard = ARSGuard::new(claims, store);

        // User can READ but not DELETE
        let result = guard.authorize_action("DELETE", "case_001.pdf").await;
        
        assert!(matches!(result, Err(AuthError::UnauthorizedAction { .. })));
    }
}
