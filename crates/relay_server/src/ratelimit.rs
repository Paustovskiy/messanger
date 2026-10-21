//! Ограничение частоты: «ведро с жетонами» на каждый ключ (аккаунт, IP, …).
//!
//! В ведре помещается `amount` жетонов, и они восстанавливаются равномерно —
//! `amount` штук за `period`. Каждое действие тратит жетон; пустое ведро — отказ.
//! Так разрешаются короткие всплески, но не долгий поток.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Сколько действий разрешено за период.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub amount: u32,
    pub period: Duration,
}

impl Rate {
    pub const fn per_minute(amount: u32) -> Self {
        Self {
            amount,
            period: Duration::from_secs(60),
        }
    }

    pub const fn per_hour(amount: u32) -> Self {
        Self {
            amount,
            period: Duration::from_secs(3600),
        }
    }

    fn refill_per_sec(&self) -> f64 {
        self.amount as f64 / self.period.as_secs_f64().max(f64::MIN_POSITIVE)
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Набор вёдер с общим тарифом.
#[derive(Debug)]
pub struct RateLimiter {
    rate: Rate,
    buckets: DashMap<String, Bucket>,
}

impl RateLimiter {
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            buckets: DashMap::new(),
        }
    }

    /// Можно ли сейчас выполнить действие для `key` (и списать жетон).
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    pub fn check_at(&self, key: &str, now: Instant) -> bool {
        let capacity = self.rate.amount as f64;
        if capacity == 0.0 {
            return false;
        }
        let mut bucket = self.buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate.refill_per_sec()).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Забыть вёдра, которые уже успели наполниться до краёв: они ничем не
    /// отличаются от новых, а память занимают.
    pub fn cleanup_at(&self, now: Instant) {
        let full_after = self.rate.period;
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < full_after);
    }

    pub fn cleanup(&self) {
        self.cleanup_at(Instant::now());
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_deny_then_refill() {
        let l = RateLimiter::new(Rate::per_minute(3));
        let t0 = Instant::now();
        assert!(l.check_at("a", t0));
        assert!(l.check_at("a", t0));
        assert!(l.check_at("a", t0));
        assert!(!l.check_at("a", t0), "bucket is empty");

        // Через 20 секунд восстанавливается ровно один жетон (3 в минуту).
        let t1 = t0 + Duration::from_secs(20);
        assert!(l.check_at("a", t1));
        assert!(!l.check_at("a", t1));

        // Через долгое время — снова полный всплеск, но не больше ёмкости.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(l.check_at("a", t2));
        }
        assert!(!l.check_at("a", t2));
    }

    #[test]
    fn keys_are_independent() {
        let l = RateLimiter::new(Rate::per_hour(1));
        let t = Instant::now();
        assert!(l.check_at("alice", t));
        assert!(!l.check_at("alice", t));
        assert!(l.check_at("bob", t));
    }

    #[test]
    fn zero_rate_denies_everything() {
        let l = RateLimiter::new(Rate::per_minute(0));
        assert!(!l.check("a"));
    }

    #[test]
    fn idle_buckets_are_cleaned_up() {
        let l = RateLimiter::new(Rate::per_minute(5));
        let t = Instant::now();
        l.check_at("old", t);
        l.check_at("fresh", t + Duration::from_secs(50));
        l.cleanup_at(t + Duration::from_secs(70));
        assert_eq!(l.len(), 1);
        // Забытое ведро ведёт себя как новое — полное.
        for _ in 0..5 {
            assert!(l.check_at("old", t + Duration::from_secs(70)));
        }
    }
}
