//! Refresh policies: configurable data describing how long collected data
//! stays fresh, whether stale reuse is permitted, and (for TTL-driven kinds
//! like DNS) how source-provided TTLs are clamped.
//!
//! Policies live in the `refresh_policies` table (seeded with defaults by the
//! v1 migration) and are read/written through the store API, so tuning cache
//! behavior never requires a rebuild.

use std::time::Duration;

/// A refresh policy for one `(kind, name)` pair.
///
/// `name` distinguishes policies within a kind: `default`, `negative` (DNS),
/// or endpoint names (`network-info`, `routing-status` for RIPEstat).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub kind: String,
    pub name: String,
    /// How long data stays fresh after `observed_at`. `None` means either
    /// *indefinitely fresh* (CT, X.509) or *TTL-driven* (DNS, when a source
    /// hint is present).
    pub fresh_for: Option<Duration>,
    /// Whether stale data may be served (labeled `Stale`, never as current).
    pub allow_stale: bool,
    /// Upper bound on how far past `fresh_until` stale reuse is permitted.
    /// `None` = unbounded. Ignored when `allow_stale` is false.
    pub stale_for: Option<Duration>,
    /// DNS: lower clamp for source-provided TTLs.
    pub ttl_min: Option<Duration>,
    /// DNS: upper clamp for source-provided TTLs.
    pub ttl_max: Option<Duration>,
}

impl Policy {
    /// Compute `fresh_until` (UTC Unix seconds) for an observation taken at
    /// `observed_at` with an optional source-provided freshness hint (e.g. a
    /// DNS TTL, or an SOA negative TTL).
    ///
    /// - Fixed policy duration wins over the source hint.
    /// - Otherwise the hint is clamped to `[ttl_min, ttl_max]` (unbounded
    ///   where the clamp is `None`).
    /// - `None` (indefinite freshness) results from no policy duration and no
    ///   source hint — e.g. CT results.
    ///
    /// `fresh_until` is never a claim of verified currency; it only drives
    /// freshness labeling.
    pub fn fresh_until(&self, observed_at: i64, source_hint: Option<Duration>) -> Option<i64> {
        let duration = match (self.fresh_for, source_hint) {
            (Some(d), _) => d,
            (None, Some(hint)) => self.clamp_ttl(hint),
            (None, None) => return None,
        };
        Some(observed_at + duration.as_secs() as i64)
    }

    /// Clamp a source-provided TTL to the policy bounds.
    pub fn clamp_ttl(&self, ttl: Duration) -> Duration {
        let mut clamped = ttl;
        if let Some(min) = self.ttl_min {
            clamped = clamped.max(min);
        }
        if let Some(max) = self.ttl_max {
            clamped = clamped.min(max);
        }
        clamped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        fresh_for: Option<Duration>,
        allow_stale: bool,
        ttl_min: Option<Duration>,
        ttl_max: Option<Duration>,
    ) -> Policy {
        Policy {
            kind: "test".into(),
            name: "default".into(),
            fresh_for,
            allow_stale,
            stale_for: None,
            ttl_min,
            ttl_max,
        }
    }

    #[test]
    fn indefinite_when_no_fresh_for_and_no_hint() {
        let p = policy(None, false, None, None);
        assert_eq!(p.fresh_until(1000, None), None);
        assert_eq!(p.fresh_until(1000, None), None);
    }

    #[test]
    fn fixed_fresh_for_overrides_source_hint() {
        let p = policy(Some(Duration::from_secs(3600)), false, None, None);
        assert_eq!(
            p.fresh_until(1000, Some(Duration::from_secs(5))),
            Some(1000 + 3600)
        );
        assert_eq!(p.fresh_until(1000, None), Some(1000 + 3600));
    }

    #[test]
    fn ttl_hint_used_when_fresh_for_is_none() {
        let p = policy(None, false, None, None);
        assert_eq!(
            p.fresh_until(1000, Some(Duration::from_secs(300))),
            Some(1300)
        );
    }

    #[test]
    fn ttl_clamped_to_policy_bounds() {
        let p = policy(
            None,
            false,
            Some(Duration::from_secs(60)),
            Some(Duration::from_secs(3600)),
        );
        assert_eq!(p.clamp_ttl(Duration::from_secs(5)), Duration::from_secs(60)); // below min
        assert_eq!(
            p.clamp_ttl(Duration::from_secs(86400)),
            Duration::from_secs(3600)
        ); // above max
        assert_eq!(
            p.clamp_ttl(Duration::from_secs(600)),
            Duration::from_secs(600)
        ); // within
        // clamped hint drives fresh_until
        assert_eq!(
            p.fresh_until(1000, Some(Duration::from_secs(86400))),
            Some(1000 + 3600)
        );
    }

    #[test]
    fn one_sided_clamps_are_unbounded_on_the_other_side() {
        let p = policy(None, false, Some(Duration::from_secs(30)), None);
        assert_eq!(p.clamp_ttl(Duration::from_secs(0)), Duration::from_secs(30));
        assert_eq!(
            p.clamp_ttl(Duration::from_secs(100_000)),
            Duration::from_secs(100_000)
        );
    }
}
