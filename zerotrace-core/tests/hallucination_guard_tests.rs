use std::sync::Arc;
use std::thread;
use zerotrace_core::interceptor::hallucination::{
    AnnotationStrategy, CitationType, HallucinationGuard, VerificationError, VerificationStatus,
};

#[test]
fn test_case_insensitive_corpus_matching() {
    // Scenario: Corpus might have different casing
    let guard = HallucinationGuard::new();
    let response = "See 123 F.3d 456.";
    let corpus = "see 123 f.3d 456 in the record."; // Lowercase

    let results = guard.verify_citations(response, corpus).unwrap();

    // Should NOT match (case-sensitive by default)
    // In production, might want case-insensitive option
    assert_eq!(results.citations[0].status, VerificationStatus::NotFound);
}

#[test]
fn test_concurrent_verification() {
    // Scenario: Guard should be thread-safe for concurrent reads
    let guard = Arc::new(HallucinationGuard::new());
    let corpus = Arc::new("123 F.3d 456 is valid.".to_string());

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let guard_clone = Arc::clone(&guard);
            let corpus_clone = Arc::clone(&corpus);
            thread::spawn(move || guard_clone.verify_citations("See 123 F.3d 456.", &corpus_clone))
        })
        .collect();

    for handle in handles {
        let result = handle.join().unwrap().unwrap();
        assert_eq!(result.metrics.verified_count, 1);
    }
}

#[test]
fn test_empty_response() {
    // Scenario: Empty input edge case
    let guard = HallucinationGuard::new();
    let results = guard.verify_citations("", "corpus").unwrap();

    assert_eq!(results.citations.len(), 0);
    assert_eq!(results.metrics.hallucination_rate, 0.0);
}

#[test]
fn test_empty_corpus() {
    // Scenario: No corpus to verify against
    let guard = HallucinationGuard::new();
    let results = guard.verify_citations("See 123 F.3d 456.", "").unwrap();

    assert_eq!(results.citations[0].status, VerificationStatus::NotFound);
}

#[test]
fn test_special_characters_in_citation() {
    // Scenario: Citations with special characters
    let guard = HallucinationGuard::new();
    let response = "See 123 F.3d 456.";
    let corpus = "123 F.3d 456";

    let results = guard.verify_citations(response, corpus).unwrap();
    assert_eq!(results.metrics.verified_count, 1);
}

#[test]
fn test_multiple_spaces_in_citation() {
    // Scenario: Irregular whitespace
    let guard = HallucinationGuard::new();
    let response = "See 123  F.3d  456."; // Double spaces
    let corpus = "123 F.3d 456";

    let results = guard.verify_citations(response, corpus).unwrap();
    // Regex should normalize whitespace if it matches, but here our regex expects specific spacing?
    // Let's check the regex. `\d{1,4}\s+` matches one or more spaces.
    // So "123  F.3d" should match.
    // But verified against corpus "123 F.3d 456" (single space).
    // Exact match will fail.
    // Fuzzy match might pass.
    // This test expects it to work?
    // Wait, the regex extracts "123  F.3d  456".
    // The corpus has "123 F.3d 456".
    // Exact match: "123  F.3d  456" != "123 F.3d 456".
    // So this test as written in the prompt might rely on regex being smart or matching failure leading to something else?
    // Actually, `verify_citations` logic:
    // 1. Extract citations. (Regex `\s+` consumes multiple spaces). Citation = "123  F.3d  456"
    // 2. Verify single citation.
    //    `corpus.contains("123  F.3d  456")` -> False.
    //    `fuzzy_matching` -> if enabled?
    // The test in the prompt (and this file) uses `HallucinationGuard::new()` which defaults to fuzzy=false.
    // So this test expects "Exact Match"?
    // Ah, wait. If the prompt's test passes, then maybe the regex behavior or matching logic handles this?
    // But logically, `strip()` or normalization isn't in `extract_citations`.
    // I suspect this test might FAIL if I implement it exactly as the user provided without thinking.
    // However, I must follow the user's provided code.
    // LIMITATION: If the user provided code fails this test, I will fix it.
    // Actually, I am generating `tests/hallucination_guard_tests.rs`. I should use the code provided.
    // I will use `HallucinationGuard::new()` as in the prompt.
    // Note: The prompt code's `test_multiple_spaces_in_citation` uses `verify_citations` and asserts `citations.len(), 1`.
    // It does NOT assert it is VERIFIED. It asserts it is EXTRACTED.
    // "Regex should normalize whitespace" -> The comment says this.
    // Assert: `results.citations.len(), 1`.
    // It doesn't check verification status. It just checks the regex matched it.
    // So it should pass.
    assert_eq!(results.citations.len(), 1);
}

#[test]
fn test_partial_citation_match() {
    // Scenario: Corpus contains citation as part of larger text
    let guard = HallucinationGuard::new();
    let response = "See 123 F.3d 456.";
    let corpus = "In 123 F.3d 456, the court held that...";

    let results = guard.verify_citations(response, corpus).unwrap();
    assert_eq!(results.citations[0].status, VerificationStatus::Verified);
}

#[test]
fn test_doi_citation() {
    // Scenario: Medical DOI citation
    let guard = HallucinationGuard::with_config(
        CitationType::Medical,
        AnnotationStrategy::InlineWarning,
        false,
    );

    let response = "See DOI: 10.1234/example.2024.";
    let corpus = "Published as DOI: 10.1234/example.2024.";

    let results = guard.verify_citations(response, corpus).unwrap();
    assert_eq!(results.citations.len(), 1);
    assert_eq!(results.citations[0].status, VerificationStatus::Verified);
}

#[test]
fn test_state_reporter_citations() {
    // Scenario: State-specific reporter formats
    let guard = HallucinationGuard::new();
    let response = "See 123 Cal.App.4th 456.";
    let corpus = "The case 123 Cal.App.4th 456 established...";

    let results = guard.verify_citations(response, corpus).unwrap();
    assert_eq!(results.citations.len(), 1);
    assert_eq!(results.citations[0].status, VerificationStatus::Verified);
}

#[test]
fn test_supreme_court_citations() {
    // Scenario: Supreme Court reporter
    let guard = HallucinationGuard::new();
    let response = "See 123 S.Ct. 456.";
    let corpus = "In 123 S.Ct. 456, the Supreme Court...";

    let results = guard.verify_citations(response, corpus).unwrap();
    assert_eq!(results.citations.len(), 1);
    assert_eq!(results.citations[0].status, VerificationStatus::Verified);
}

#[test]
fn test_very_long_citation() {
    // Scenario: Abnormally long citation (possible attack)
    let guard = HallucinationGuard::new();
    // 100 digits usually doesn't match \d{1,4} or \d{1,5}
    // But the regex says `\d{1,4}` volume, `\d{1,5}` page.
    // The constructor format: `format!("{} F.3d {}", "1".repeat(100), "2".repeat(100))`
    // This creates "111...111 F.3d 222...222".
    // 100 digits for volume? Regex expects `\d{1,4}`.
    // So the regex will NOT match "11111111...".
    // Thus `extract_citations` should return empty or valid parts if any.
    // The test asserts `results.citations.len() >= 0`, which is always true.
    // It effectively tests that it doesn't panic on long inputs.
    let long_citation = format!("{} F.3d {}", "1".repeat(100), "2".repeat(100));
    let response = format!("See {}.", long_citation);
    let corpus = "No match";

    let results = guard.verify_citations(&response, corpus).unwrap();
    // Should still process (within token limits)
    assert!(results.citations.len() >= 0);
}

#[test]
fn test_zero_confidence() {
    // Scenario: Not found should have 0 confidence
    let guard = HallucinationGuard::new();
    let results = guard.verify_citations("See 999 F.3d 000.", "").unwrap();

    assert_eq!(results.citations[0].confidence, 0.0);
}

#[test]
fn test_average_confidence_calculation() {
    // Scenario: Verify average confidence calculation
    let guard = HallucinationGuard::new();
    let response = "See 123 F.3d 456 and 999 F.3d 000.";
    let corpus = "123 F.3d 456 is valid.";

    let results = guard.verify_citations(response, corpus).unwrap();

    // 1 verified (1.0 confidence) + 1 not found (0.0 confidence) = avg 0.5
    assert_eq!(results.metrics.average_confidence, 0.5);
}
