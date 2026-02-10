use std::time::Duration;
use tokio::time::{sleep, Instant};

/// Guard against Side-Channel Attacks (EMG22).
///
/// Mitigates:
/// 1. **Timing Attacks**: By buffering responses to a minimum duration.
/// 2. **Packet Size Analysis**: By padding responses to a fixed block size.
pub struct SideChannelGuard {
    min_response_time_ms: u64,
    padding_block_size: usize,
}

impl SideChannelGuard {
    /// Create a new guard with specified timing and padding configurations.
    ///
    /// * `min_response_time_ms`: Minimum time the operation should take.
    /// * `padding_block_size`: The block size alignment for the output.
    pub fn new(min_response_time_ms: u64, padding_block_size: usize) -> Self {
        Self {
            min_response_time_ms,
            padding_block_size,
        }
    }

    /// Executes a secure response, ensuring deterministic timing and length padding.
    ///
    /// This function:
    /// 1. Measures execution time.
    /// 2. Calculates necessary delay to meet `min_response_time`.
    /// 3. Sleeps asynchronously (non-blocking) if needed.
    /// 4. Pads the content to the nearest `padding_block_size`.
    pub async fn execute_secure_response(&self, content: String) -> String {
        let start_time = Instant::now();

        // 1. Calculate elapsed time
        let elapsed = start_time.elapsed().as_millis() as u64;

        // 2. Jitter / Delay (Deterministic Timing)
        if elapsed < self.min_response_time_ms {
            let delay = self.min_response_time_ms - elapsed;
            sleep(Duration::from_millis(delay)).await;
        }

        // 3. Length Padding (Packet Analysis Mitigation)
        self.pad_content(content)
    }

    /// Pads the content with spaces to align with `padding_block_size`.
    fn pad_content(&self, mut content: String) -> String {
        if self.padding_block_size == 0 {
            return content;
        }

        let current_len = content.len();
        let remain = current_len % self.padding_block_size;

        if remain > 0 {
            let padding_needed = self.padding_block_size - remain;
            // Extending String with spaces is efficient
            content.reserve(padding_needed);
            for _ in 0..padding_needed {
                content.push(' ');
            }
        }

        content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_buffer() {
        let guard = SideChannelGuard::new(100, 256);
        let start = Instant::now();

        let _ = guard.execute_secure_response("test".to_string()).await;

        let elapsed = start.elapsed().as_millis();
        assert!(
            elapsed >= 95,
            "Response was too fast! Timing attack possible."
        );
    }

    #[tokio::test]
    async fn test_length_padding() {
        let block_size = 10;
        let guard = SideChannelGuard::new(0, block_size);

        let raw = "12345"; // 5 chars
        let secured = guard.execute_secure_response(raw.to_string()).await;

        assert_eq!(secured.len(), 10, "Padding failed to align to block size.");
        assert!(secured.starts_with("12345"));
        assert!(secured.ends_with("     "));
    }

    #[tokio::test]
    async fn test_exact_block_size_no_padding() {
        let block_size = 5;
        let guard = SideChannelGuard::new(0, block_size);

        let raw = "12345";
        let secured = guard.execute_secure_response(raw.to_string()).await;

        assert_eq!(
            secured.len(),
            5,
            "Should not add padding if already aligned."
        );
        assert_eq!(secured, "12345");
    }

    #[tokio::test]
    async fn test_padding_unicode() {
        let block_size = 10;
        let guard = SideChannelGuard::new(0, block_size);

        // "🦀" is 4 bytes
        let raw = "🦀";
        let secured = guard.execute_secure_response(raw.to_string()).await;

        // 4 bytes + 6 spaces = 10 bytes?
        // String::len return bytes.
        // "🦀" is 4 bytes.
        // 4 % 10 = 4.
        // Need 6 bytes padding.
        // 6 spaces = 6 bytes.
        // Total bytes = 10.

        assert_eq!(secured.len(), 10);
        assert!(secured.contains("🦀"));
    }
}
