use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ProbabilisticRateLimiter {
    // Simplified Token Bucket for V1
    // In a real system, this would be Redis/Memcached keyed by IP/User
    tokens: AtomicUsize,
    max_tokens: usize,
    refill_rate_per_sec: usize,
    last_refill: AtomicUsize,
}

impl Default for ProbabilisticRateLimiter {
    fn default() -> Self {
        Self::new(100, 10) // 100 burst, 10/sec
    }
}

impl ProbabilisticRateLimiter {
    pub fn new(max_tokens: usize, refill_rate: usize) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        Self {
            tokens: AtomicUsize::new(max_tokens),
            max_tokens,
            refill_rate_per_sec: refill_rate,
            last_refill: AtomicUsize::new(now),
        }
    }

    pub fn check_rate_limit(&self) -> bool {
        self.refill();

        // "False Positive Flooding" attack (V42): Attacker floods with junk to hide real attack.
        // We drop requests probabilistically if load is high?
        // For V1, we just do strict limiting.

        let current = self.tokens.load(Ordering::SeqCst);
        if current > 0 {
            // Decrement
            self.tokens.fetch_sub(1, Ordering::SeqCst);
            true // Allowed
        } else {
            false // Blocked
        }
    }

    fn refill(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let last = self.last_refill.load(Ordering::Relaxed);

        if now > last {
            let elapsed = now - last;
            let added = elapsed * self.refill_rate_per_sec;
            let current = self.tokens.load(Ordering::Relaxed);
            let new_level = (current + added).min(self.max_tokens);

            // simple compare_exchange to update, ignore fails (race is fine, just skips a partial refill)
            if self
                .last_refill
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                self.tokens.store(new_level, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_v42_rate_limit_blocking() {
        // 2 tokens max, 1 refill per sec
        let limiter = ProbabilisticRateLimiter::new(2, 1);

        assert!(limiter.check_rate_limit()); // 1 left
        assert!(limiter.check_rate_limit()); // 0 left
        assert!(!limiter.check_rate_limit()); // Blocked
    }

    #[test]
    fn test_v42_refill() {
        let limiter = ProbabilisticRateLimiter::new(1, 10); // 1 token, fast refill
        assert!(limiter.check_rate_limit()); // 0 left
        assert!(!limiter.check_rate_limit()); // Blocked

        sleep(Duration::from_millis(1100)); // Wait > 1 sec

        assert!(limiter.check_rate_limit()); // Should have refilled
    }
}
