use crate::interceptor::detect::TyposquatEngine;
use std::collections::HashSet;

pub struct SlopsquatDetector {
    verified_packages: HashSet<String>,
    typosquat_engine: TyposquatEngine,
}

impl SlopsquatDetector {
    pub fn new() -> Self {
        // In a real system, this would load from a dynamic source (Redis/Postgres).
        // For now, we seed with a "Verified Mirror" subset.
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        verified.insert("numpy".to_string());
        verified.insert("pandas".to_string());
        verified.insert("react".to_string());
        verified.insert("express".to_string());
        verified.insert("tokio".to_string());
        verified.insert("serde".to_string());

        SlopsquatDetector {
            verified_packages: verified.clone(),
            typosquat_engine: TyposquatEngine::new(verified.into_iter().collect()),
        }
    }

    /// Scans a prompt for dangerous package installation commands.
    /// Returns `true` if a risk (Slopsquatting/Hallucination) is detected.
    pub fn detect_package_risk(&self, prompt: &str) -> bool {
        let prompt_lower = prompt.to_lowercase();
        
        // simple heuristic to find package names
        let patterns = vec!["pip install ", "npm install ", "cargo add "];
        
        for pattern in patterns {
            if let Some(idx) = prompt_lower.find(pattern) {
                let rest = &prompt_lower[idx + pattern.len()..];
                let package_name = rest.split_whitespace().next().unwrap_or("").trim();
                
                if !package_name.is_empty() {
                    // 1. Direct Verification Check
                    if self.verified_packages.contains(package_name) {
                        continue; // Safe
                    }

                    // 2. Typosquat Check (Hallucination Squatting)
                    // If it's close to a verified package but not exact, it's a risk.
                    if self.typosquat_engine.is_typosquat(package_name) {
                        println!("Slopsquat Detection: Package '{}' resembles verified package.", package_name);
                        return true;
                    }
                    
                    // 3. Unverified "Slop" Check (Unknown Package)
                    // For strict environments, block anything not in verified list.
                    println!("Slopsquat Detection: Unverified package '{}' requested.", package_name);
                    return true;
                }
            }
        }
        
        false
    }
}
