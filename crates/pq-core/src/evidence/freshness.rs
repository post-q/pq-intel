//! Freshness contract and evaluation.
//!
//! The API contract is adopted verbatim from the long-form spec (§9.5):
//! `FreshnessRequirement` is what a consumer asks for; `DataStatus` is the
//! honest label of what came back. Labels never lie: stale data is returned
//! only where the policy permits stale reuse and is always labeled `Stale`,
//! never presented as current.

use crate::evidence::observation::StoredObservation;
use crate::evidence::policy::Policy;
use chrono::{DateTime, Utc};

/// What freshness does the consumer require?
#[derive(Clone, Debug)]
pub enum FreshnessRequirement {
    /// Serve the newest usable observation from the store, whatever its age,
    /// honestly labeled (possibly `Stale` or `Expired`). Never touches the
    /// network; [`DataStatus::Unavailable`] when nothing is stored. Use for
    /// offline/inspection paths and bulk sweeps that must not hammer a
    /// shared provider.
    Cached,
    /// Serve from the store only when the last usable observation is at most
    /// `d` old AND the policy permits reuse; otherwise collect (blocking).
    /// Correctness-first reads pass a bound matching the path's tolerance;
    /// the policy still governs the honest label.
    MaxAge(std::time::Duration),
    /// Re-collect regardless of cache state.
    Refresh,
    /// The observation as of the given time, from history; never touches the
    /// network.
    Historical { at: DateTime<Utc> },
}

/// Honest label of a stored observation's state relative to the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataStatus {
    /// Within the policy-derived freshness window.
    Fresh,
    /// Past `fresh_until`, but the policy permits stale reuse. Never a claim
    /// of verified currency.
    Stale,
    /// Past `fresh_until` and the policy does not permit reuse.
    Expired,
    /// Nothing usable in the store.
    Unavailable,
}

/// Evaluate the status of the latest usable observation under `policy`.
///
/// `at` is the reference time: `now` for live reads, the historical instant
/// for `Historical` reads.
pub fn evaluate(at: i64, latest: Option<&StoredObservation>, policy: &Policy) -> DataStatus {
    let Some(obs) = latest else {
        return DataStatus::Unavailable;
    };
    match obs.fresh_until {
        // Indefinite freshness (e.g. CT, X.509).
        None => DataStatus::Fresh,
        Some(fresh_until) => {
            if at < fresh_until {
                DataStatus::Fresh
            } else if policy.allow_stale
                && policy
                    .stale_for
                    .is_none_or(|cap| (at - fresh_until) <= cap.as_secs() as i64)
            {
                DataStatus::Stale
            } else {
                DataStatus::Expired
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::key::CollectionRequest;
    use crate::evidence::observation::{ObservationStatus, StoredObservation};
    use serde_json::json;

    fn dummy_key() -> crate::evidence::key::CollectionKey {
        struct R;
        impl CollectionRequest for R {
            const KIND: &'static str = "test";
            fn write_canonical(&self, _w: &mut crate::evidence::key::CanonicalWriter) {}
            fn stored_params(&self) -> serde_json::Value {
                json!(null)
            }
        }
        crate::evidence::key::CollectionKey::compute("test", &R)
    }

    fn obs(fresh_until: Option<i64>, observed_at: i64) -> StoredObservation {
        StoredObservation {
            id: 1,
            key: dummy_key(),
            kind: "test".into(),
            status: ObservationStatus::Success,
            native_status: None,
            observed_at,
            source_time: None,
            fresh_until,
            metadata: json!({}),
            artifacts: vec![],
            scan_id: 1,
        }
    }

    fn policy(allow_stale: bool, stale_for: Option<u64>) -> Policy {
        Policy {
            kind: "test".into(),
            name: "default".into(),
            fresh_for: Some(std::time::Duration::from_secs(600)),
            allow_stale,
            stale_for: stale_for.map(std::time::Duration::from_secs),
            ttl_min: None,
            ttl_max: None,
        }
    }

    #[test]
    fn nothing_usable_is_unavailable() {
        let p = policy(false, None);
        assert_eq!(evaluate(1000, None, &p), DataStatus::Unavailable);
    }

    #[test]
    fn within_fresh_window_is_fresh() {
        let p = policy(false, None);
        // observed_at=1000, fresh window 600 → fresh until 1600
        assert_eq!(
            evaluate(1599, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Fresh
        );
        assert_eq!(
            evaluate(1000, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Fresh
        );
    }

    #[test]
    fn past_fresh_until_labeled_by_stale_permission() {
        let p = policy(true, None);
        assert_eq!(
            evaluate(1600, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Stale
        );
        let strict = policy(false, None);
        assert_eq!(
            evaluate(1600, Some(&obs(Some(1600), 1000)), &strict),
            DataStatus::Expired
        );
    }

    #[test]
    fn stale_window_caps_stale_reuse() {
        let p = policy(true, Some(100));
        assert_eq!(
            evaluate(1699, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Stale
        );
        assert_eq!(
            evaluate(1700, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Stale
        );
        assert_eq!(
            evaluate(1701, Some(&obs(Some(1600), 1000)), &p),
            DataStatus::Expired
        );
    }

    #[test]
    fn indefinite_fresh_until_is_always_fresh() {
        let p = policy(false, None);
        assert_eq!(
            evaluate(10_000_000, Some(&obs(None, 1000)), &p),
            DataStatus::Fresh
        );
    }

    #[test]
    fn failed_observations_are_not_labeled() {
        // Status evaluation only ever sees usable observations; the store
        // guarantees `latest` is usable. Nothing to assert beyond the contract
        // that evaluation is purely time/policy math.
        let p = policy(false, None);
        let mut o = obs(Some(1600), 1000);
        o.status = ObservationStatus::Error;
        // Evaluation does not consult status; callers pass usable obs only.
        assert_eq!(evaluate(1000, Some(&o), &p), DataStatus::Fresh);
    }
}
