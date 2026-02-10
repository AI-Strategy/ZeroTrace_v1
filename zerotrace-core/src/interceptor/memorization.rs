use regex::Regex;
use std::borrow::Cow;

pub struct TrainingDataScrubber {
    // Regex patterns for PII
    ssn_regex: Regex,
    email_regex: Regex,
    phone_regex: Regex,
}

impl TrainingDataScrubber {
    pub fn new() -> Self {
        Self {
            // Simplified regexes for demonstration of the "Scrubbing Pipeline"
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            email_regex: Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap(),
            phone_regex: Regex::new(r"\b\d{3}-\d{3}-\d{4}\b").unwrap(),
        }
    }

    /// Sanitizes raw legal text to prevent "Training Data Memorization" (EXT17).
    /// Replaces identifying information with structural tokens.
    pub fn sanitize_for_training<'a>(&self, raw_legal_text: &'a str) -> Cow<'a, str> {
        let mut text = Cow::Borrowed(raw_legal_text);

        // 1. Scrub SSNs
        if self.ssn_regex.is_match(&text) {
             text = Cow::Owned(self.ssn_regex.replace_all(&text, "<SSN_REDACTED>").to_string());
        }

        // 2. Scrub Emails
        if self.email_regex.is_match(&text) {
            text = Cow::Owned(self.email_regex.replace_all(&text, "<EMAIL_REDACTED>").to_string());
        }

        // 3. Scrub Phone Numbers
        if self.phone_regex.is_match(&text) {
            text = Cow::Owned(self.phone_regex.replace_all(&text, "<PHONE_REDACTED>").to_string());
        }

        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_ssn() {
        let scrubber = TrainingDataScrubber::new();
        let input = "Client ID is 123-45-6789 for the file.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, "Client ID is <SSN_REDACTED> for the file.");
    }

    #[test]
    fn test_scrub_email() {
        let scrubber = TrainingDataScrubber::new();
        let input = "Contact john.doe@example.com immediately.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, "Contact <EMAIL_REDACTED> immediately.");
    }

    #[test]
    fn test_no_change_clean_text() {
        let scrubber = TrainingDataScrubber::new();
        let input = "The court ruled in favor of the defendant.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, input);
    }
    
     #[test]
    fn test_multiple_redactions() {
        let scrubber = TrainingDataScrubber::new();
        let input = "Call 555-123-4567 or email jane@test.co regarding 987-65-4320.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, "Call <PHONE_REDACTED> or email <EMAIL_REDACTED> regarding <SSN_REDACTED>.");
    }
}
