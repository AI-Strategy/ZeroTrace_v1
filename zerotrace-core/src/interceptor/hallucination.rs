use regex::Regex;

pub struct HallucinationGuard {
    citation_regex: Regex,
}

impl HallucinationGuard {
    pub fn new() -> Self {
        // Regex for legal citations (e.g., "123 F.3d 456")
        // Basic pattern matching common US legal citation formats
        Self {
            citation_regex: Regex::new(r"\d+\s+[A-Z]\.\d+d?\s+\d+").unwrap(),
        }
    }

    pub fn verify_and_annotate(&self, llm_response: &str, trusted_corpus: &str) -> String {
        let mut verified_output = llm_response.to_string();

        // 1. Extract and check citations against the "Ground Truth"
        // We collect matches first to avoid issues with modifying the string while iterating (though replacement creates new strings)
        // Simplest approach: multiple passes or careful replacement.
        // Since we are replacing with a warning, let's process matches.
        
        let mut citations_to_flag = Vec::new();
        
        for mat in self.citation_regex.find_iter(llm_response) {
            let citation = mat.as_str();
            
            if !trusted_corpus.contains(citation) {
                // 2. FLAG: Hallucination Detected
                // Check if we already flagged this citation to avoid double replacement if mentioned multiple times
                if !citations_to_flag.contains(&citation.to_string()) {
                    citations_to_flag.push(citation.to_string());
                }
            }
        }

        for citation in citations_to_flag {
             let warning = format!("{} [WARNING: SOURCE NOT FOUND]", citation);
             verified_output = verified_output.replace(&citation, &warning);
        }
        
        verified_output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_citation() {
        let guard = HallucinationGuard::new();
        let response = "As seen in 123 F.3d 456, the ruling stands.";
        let corpus = "The case 123 F.3d 456 discusses...";
        
        let result = guard.verify_and_annotate(response, corpus);
        assert_eq!(result, response);
    }

    #[test]
    fn test_hallucinated_citation() {
        let guard = HallucinationGuard::new();
        let response = "As seen in 999 F.3d 000, the ruling stands.";
        let corpus = "The case 123 F.3d 456 discusses..."; // Corpus does NOT have 999 F.3d 000
        
        let result = guard.verify_and_annotate(response, corpus);
        assert!(result.contains("999 F.3d 000 [WARNING: SOURCE NOT FOUND]"));
    }

    #[test]
    fn test_multiple_citations_mixed() {
        let guard = HallucinationGuard::new();
        let response = "Compare 123 F.3d 456 with 999 F.3d 000.";
        let corpus = "123 F.3d 456 is valid."; 
        
        let result = guard.verify_and_annotate(response, corpus);
        // Valid one stays
        assert!(result.contains("123 F.3d 456")); 
        // Invalid one gets flagged
        assert!(result.contains("999 F.3d 000 [WARNING: SOURCE NOT FOUND]"));
    }
}
