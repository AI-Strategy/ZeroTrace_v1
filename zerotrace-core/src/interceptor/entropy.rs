use regex::Regex;

/// Calculates the Shannon entropy of a given string.
/// Higher entropy often indicates random strings like keys or encrypted data.
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut frequency = std::collections::HashMap::new();
    for ch in s.chars() {
        *frequency.entry(ch).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    frequency.values().fold(0.0, |entropy, &count| {
        let p = count as f64 / len;
        entropy - p * p.log2()
    })
}

/// Scans for high-entropy strings and known API key patterns.
pub fn scan_for_secrets(input: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // 1. Pattern Matching for known key formats
    // AWS Access Key ID (AKIA...)
    let aws_regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    if aws_regex.is_match(input) {
        warnings.push("SECRET_LEAK:AWS_ACCESS_KEY".to_string());
    }

    // OpenAI Key (sk-...) - simplified for example
    let openai_regex = Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap();
    if openai_regex.is_match(input) {
        warnings.push("SECRET_LEAK:OPENAI_KEY".to_string());
    }

    // 2. High Entropy Word Scanning
    // Split by whitespace and check each "word"
    for word in input.split_whitespace() {
        if word.len() > 20 {
            // short words rarely have high enough entropy to matter for keys
            let entropy = calculate_shannon_entropy(word);
            // Threshold is heuristic; 4.5 is a common start point for base64/random strings
            if entropy > 4.5 {
                // Ignore likely non-secret long strings (like URLs) if needed,
                // but for now, flag it.
                warnings.push(format!("HIGH_ENTROPY_STRING_DETECTED:{:.2}", entropy));
            }
        }
    }

    warnings
}
