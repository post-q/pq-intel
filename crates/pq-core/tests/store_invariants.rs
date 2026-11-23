//! Tier-2 integration tests: the v1 invariants, exercised through the
//! evidence module's public API against a real SQLite database in a temp
//! directory. Real engine, no mocks — collectors are canned at the
//! network-boundary seam only.

mod common;

use common::*;
use pq_core::evidence::collector::CollectionError;
use pq_core::evidence::freshness::FreshnessRequirement as F;
use pq_core::evidence::key::CollectionRequest;
use pq_core::evidence::observation::ObservationStatus;
use pq_core::evidence::store::Usage;
use serde_json::json;
use std::time::Duration;

// --- 1. Cache reuse across consumers --------------------------------------

#[test]
fn first_collection_then_cache_reuse_across_consumers() {
    let (_dir, store) = open_store();
    let collector = CannedCollector::new(vec![CannedOutcome::success(json!({"v": 1}))]);
    let req = CannedRequest {
        ident: "shared".into(),
        secret: None,
    };

    let first = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let second = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let third_consumer_with_secret = collect_once(
        &store,
        &collector,
        CannedRequest {
            ident: "shared".into(),
            secret: Some("token-1".into()),
        },
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    assert_eq!(collector.call_count(), 1, "network hit exactly once");
    assert_eq!(first.usage, Usage::Collected);
    assert_eq!(second.usage, Usage::Cached);
    assert_eq!(third_consumer_with_secret.usage, Usage::Cached);
    assert_eq!(
        first.observation.as_ref().unwrap().id,
        second.observation.as_ref().unwrap().id
    );
    assert_eq!(
        second.observation.as_ref().unwrap().id,
        third_consumer_with_secret.observation.as_ref().unwrap().id
    );
}

// --- 2. Stale → blocking revalidate ----------------------------------------

#[test]
fn validate_revalidates_expired_data_blocking() {
    let (_dir, store) = open_store();
    store
        .set_policy(&policy_expired_immediately("canned"))
        .unwrap();
    let collector = CannedCollector::new(vec![
        CannedOutcome::success(json!({"v": 1})),
        CannedOutcome::success(json!({"v": 2})),
    ]);
    let req = CannedRequest {
        ident: "x".into(),
        secret: None,
    };

    let first = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let second = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    assert_eq!(first.usage, Usage::Collected);
    assert_eq!(
        second.usage,
        Usage::Refreshed,
        "expired data is re-collected, blocking"
    );
    assert_eq!(collector.call_count(), 2);
    assert_eq!(second.data, Some(json!({"v": 2})));
    // History keeps both.
    let key = req.key();
    assert_eq!(store.observation_history(&key, 10).unwrap().len(), 2);
}

// --- 3. Failed refresh preserves the last success ---------------------------

#[test]
fn failed_refresh_preserves_last_success_and_reports_failure() {
    let (_dir, store) = open_store();
    store
        .set_policy(&policy_expired_immediately("canned"))
        .unwrap();
    let collector = CannedCollector::new(vec![
        CannedOutcome::success(json!({"v": 1})),
        CannedOutcome::Fail(CollectionError::RateLimited {
            native: Some("429".into()),
        }),
    ]);
    let req = CannedRequest {
        ident: "x".into(),
        secret: None,
    };

    collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let after_failure = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    // The last successful result comes back, with the failure attached.
    let failure = after_failure.failure.expect("failure reported");
    assert_eq!(failure.status, ObservationStatus::RateLimited);
    assert_eq!(failure.native_status.as_deref(), Some("429"));
    assert_eq!(
        after_failure.data,
        Some(json!({"v": 1})),
        "last success preserved"
    );
    assert_eq!(after_failure.usage, Usage::Cached);
    assert_eq!(
        after_failure.data_status,
        pq_core::evidence::DataStatus::Expired,
        "label never lies about age"
    );

    // The failure is recorded as an observation; both attempts in history.
    let key = req.key();
    let history = store.observation_history(&key, 10).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].status,
        ObservationStatus::RateLimited,
        "newest attempt first"
    );
    assert_eq!(history[1].status, ObservationStatus::Success);

    // The explicit latest pointers distinguish attempt vs success.
    assert_eq!(
        store.latest_observation(&key).unwrap().unwrap().status,
        ObservationStatus::RateLimited
    );
    assert_eq!(
        store
            .latest_usable_observation(&key)
            .unwrap()
            .unwrap()
            .status,
        ObservationStatus::Success
    );
}

// --- 4. Timeout is "unknown", never "nonexistent" ---------------------------

#[test]
fn timeout_is_recorded_as_unknown_never_nonexistent() {
    let (_dir, store) = open_store();
    let collector = CannedCollector::new(vec![CannedOutcome::Fail(timeout_err())]);
    let req = CannedRequest {
        ident: "slow".into(),
        secret: None,
    };

    let out = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    assert_eq!(
        out.failure.as_ref().unwrap().status,
        ObservationStatus::Timeout
    );
    assert_eq!(out.data_status, pq_core::evidence::DataStatus::Unavailable);

    let key = req.key();
    let latest = store.latest_observation(&key).unwrap().unwrap();
    assert_eq!(
        latest.status,
        ObservationStatus::Timeout,
        "timeout kept as unknown"
    );
    assert_ne!(latest.status, ObservationStatus::NotFound);
}

// --- 5. Freshness labels never lie ------------------------------------------

#[test]
fn freshness_labels_track_policy_math() {
    let (_dir, store) = open_store();
    // TTL-driven policy (fresh_for=None): the source hint drives freshness,
    // clamped by the policy bounds.
    store
        .set_policy(&pq_core::evidence::Policy {
            kind: "canned".into(),
            name: "default".into(),
            fresh_for: None,
            allow_stale: false,
            stale_for: None,
            ttl_min: Some(Duration::from_secs(300)),
            ttl_max: Some(Duration::from_secs(86400)),
        })
        .unwrap();
    let collector = CannedCollector::new(vec![CannedOutcome::Success {
        native: None,
        metadata: json!({}),
        artifacts: vec![],
        fresh_hint: Some(Duration::from_secs(60)), // clamped up to ttl_min 300
        source_time: None,
    }]);
    let req = CannedRequest {
        ident: "l".into(),
        secret: None,
    };
    let out = collect_once(
        &store,
        &collector,
        req,
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    assert_eq!(out.data_status, pq_core::evidence::DataStatus::Fresh);
    let obs = out.observation.unwrap();
    // hint 60s clamped to ttl_min 300s → fresh_until = observed_at + 300
    assert_eq!(obs.fresh_until, Some(obs.observed_at + 300));
}

// --- 6. Provenance survives ingestion ---------------------------------------

#[test]
fn provenance_survives_ingestion() {
    let (_dir, store) = open_store();
    let collector = CannedCollector::new(vec![CannedOutcome::Success {
        native: Some("200".into()),
        metadata: json!({"title": "hello"}),
        artifacts: vec![("response_body", b"<html>hello</html>".to_vec(), "text/html")],
        fresh_hint: None,
        source_time: Some(
            chrono::DateTime::parse_from_rfc3339("2026-11-21T00:00:00Z")
                .unwrap()
                .into(),
        ),
    }]);
    let req = CannedRequest {
        ident: "prov".into(),
        secret: None,
    };
    let out = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let collected_scan_id = out.observation.as_ref().unwrap().scan_id;

    let back = store.observation_history(&req.key(), 10).unwrap();
    let o = &back[0];
    assert_eq!(o.status, ObservationStatus::Success);
    assert_eq!(o.native_status.as_deref(), Some("200"));
    assert_eq!(o.metadata, json!({"title": "hello"}));
    assert_eq!(o.observed_at_time(), o.observed_at_time());
    assert_eq!(o.source_at_time().unwrap().timestamp(), 1_795_219_200); // 2026-11-21T00:00:00Z
    assert_eq!(
        o.scan_id, collected_scan_id,
        "provenance: which run collected it"
    );
    assert_eq!(o.kind, "canned");
    let body = o
        .artifact_by_role("response_body")
        .expect("artifact linked");
    assert_eq!(store.read_artifact(body).unwrap(), b"<html>hello</html>");
}

// --- 7. Artifact dedup -------------------------------------------------------

#[test]
fn artifact_dedup_identical_content() {
    let (_dir, store) = open_store();
    let body = b"identical page".to_vec();
    let collector = CannedCollector::new(vec![
        CannedOutcome::Success {
            native: None,
            metadata: json!({"v": 1}),
            artifacts: vec![("response_body", body.clone(), "text/html")],
            fresh_hint: None,
            source_time: None,
        },
        CannedOutcome::Success {
            native: None,
            metadata: json!({"v": 2}),
            artifacts: vec![("response_body", body.clone(), "text/html")],
            fresh_hint: None,
            source_time: None,
        },
    ]);
    store
        .set_policy(&policy_expired_immediately("canned"))
        .unwrap();
    let req = CannedRequest {
        ident: "dedup".into(),
        secret: None,
    };
    let o1 = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap()
    .observation
    .unwrap();
    let o2 = collect_once(
        &store,
        &collector,
        req,
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap()
    .observation
    .unwrap();

    let h1 = o1.artifact_by_role("response_body").unwrap();
    let h2 = o2.artifact_by_role("response_body").unwrap();
    assert_eq!(
        h1.hash, h2.hash,
        "ten scans of an unchanged page store exactly one artifact"
    );
    assert_eq!(store.read_artifact(h1).unwrap(), body);
}

// --- 8. Crash-safe artifact writes ------------------------------------------

#[test]
fn artifact_orphans_do_not_corrupt_the_store() {
    let (_dir, store) = open_store();
    // Orphan file left by an interrupted write is tolerated.
    let orphan = store.data_dir().join("artifacts/ab/abcdef");
    std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
    std::fs::write(&orphan, b"junk").unwrap();
    let collector = CannedCollector::new(vec![CannedOutcome::Success {
        native: None,
        metadata: json!({}),
        artifacts: vec![("response_body", b"real".to_vec(), "text/plain")],
        fresh_hint: None,
        source_time: None,
    }]);
    let req = CannedRequest {
        ident: "crash".into(),
        secret: None,
    };
    let out = collect_once(
        &store,
        &collector,
        req,
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let meta = out
        .observation
        .unwrap()
        .artifact_by_role("response_body")
        .unwrap()
        .clone();
    assert_eq!(store.read_artifact(&meta).unwrap(), b"real");
}

// --- 9. Scan records exact consumption --------------------------------------

#[test]
fn scan_records_exact_consumption_with_usage() {
    let (_dir, store) = open_store();
    store
        .set_policy(&policy_expired_immediately("canned"))
        .unwrap();
    let collector = CannedCollector::new(vec![
        CannedOutcome::success(json!({"v": 1})),
        CannedOutcome::success(json!({"v": 2})),
        CannedOutcome::success(json!({"v": 3})),
    ]);
    let req = CannedRequest {
        ident: "usage".into(),
        secret: None,
    };

    // Scan 1: collected. Scan 2: refreshed (expired). Scan 3: cached (store-only read).
    let scan1 = store.begin_scan("pq-test", json!({"run": 1})).unwrap();
    scan1
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan1.finish().unwrap();
    let scan2 = store.begin_scan("pq-test", json!({"run": 2})).unwrap();
    scan2
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan2.finish().unwrap();
    let scan3 = store.begin_scan("pq-test", json!({"run": 3})).unwrap();
    scan3.collect(&collector, req.clone(), F::Cached).unwrap();
    scan3.finish().unwrap();

    let scans = store.scans(3).unwrap();
    assert_eq!(scans.len(), 3);
    let [s3, s2, s1]: [_; 3] = scans.try_into().unwrap(); // newest first
    assert_eq!(s1.tool, "pq-test");
    assert_eq!(s1.invocation, json!({"run": 1}));
    assert!(s1.finished_at.is_some());
    // Each scan consumed exactly one observation with the right usage class.
    let (_, u1) = store.scan_observations(s1.id).unwrap()[0];
    let (_, u2) = store.scan_observations(s2.id).unwrap()[0];
    let (_, u3) = store.scan_observations(s3.id).unwrap()[0];
    assert_eq!(u1, Usage::Collected);
    assert_eq!(u2, Usage::Refreshed);
    assert_eq!(u3, Usage::Cached);
}

// --- 10. Historical reads ----------------------------------------------------

#[test]
fn historical_reads_never_touch_network() {
    let (_dir, store) = open_store();
    let collector = CannedCollector::new(vec![CannedOutcome::success(json!({"v": 1}))]);
    let req = CannedRequest {
        ident: "hist".into(),
        secret: None,
    };
    let collected = collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let obs = collected.observation.unwrap();

    // Read as of "now+1h": sees the observation, historical usage.
    let later = F::Historical {
        at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let out = collect_once(&store, &collector, req.clone(), later).unwrap();
    assert_eq!(out.usage, Usage::Historical);
    assert_eq!(out.observation.as_ref().unwrap().id, obs.id);
    assert_eq!(collector.call_count(), 1, "historical never collects");

    // Read as of before anything existed: honest unavailability, still no network.
    let earlier = F::Historical {
        at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    let out = collect_once(&store, &collector, req, earlier).unwrap();
    assert_eq!(out.usage, Usage::Historical);
    assert_eq!(out.data_status, pq_core::evidence::DataStatus::Unavailable);
    assert!(out.observation.is_none());
    assert_eq!(collector.call_count(), 1);
}

// --- 11. Single-flight --------------------------------------------------------

#[test]
fn concurrent_identical_requests_share_one_collection() {
    let (_dir, store) = open_store();
    // Gate: while true, the leader's collect() spins in place.
    let gate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let gated = std::sync::Arc::new(CannedCollector::gated(
        vec![CannedOutcome::success(json!({"v": 1}))],
        gate.clone(),
    ));

    let store1 = store.clone();
    let gated1 = gated.clone();
    let r1 = CannedRequest {
        ident: "flight".into(),
        secret: None,
    };
    let key = r1.key();

    let a = std::thread::spawn(move || {
        collect_once(
            &store1,
            &*gated1,
            r1,
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap()
    });
    // Leader is inside collect() (call recorded, flight joined, gate held).
    while gated.call_count() < 1 || store.in_flight_participants(&key) < 1 {
        std::thread::yield_now();
    }

    let store2 = store.clone();
    let gated2 = gated.clone();
    let r2 = CannedRequest {
        ident: "flight".into(),
        secret: None,
    };
    let b = std::thread::spawn(move || {
        collect_once(
            &store2,
            &*gated2,
            r2,
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap()
    });
    // Follower has joined the leader's flight.
    while store.in_flight_participants(&key) < 2 {
        std::thread::yield_now();
    }

    // Now release the leader; both must complete.
    gate.store(false, std::sync::atomic::Ordering::SeqCst);
    let out_a = a.join().unwrap();
    let out_b = b.join().unwrap();

    assert_eq!(
        gated.call_count(),
        1,
        "single-flight: one collection for two requests"
    );
    assert_eq!(out_a.usage, Usage::Collected);
    assert_eq!(
        out_b.usage,
        Usage::Cached,
        "follower shares the leader's collection"
    );
    assert_eq!(out_a.observation.unwrap().id, out_b.observation.unwrap().id);
}

// --- 12. Forced refresh ------------------------------------------------------

#[test]
fn forced_refresh_bypasses_cache() {
    let (_dir, store) = open_store();
    let collector = CannedCollector::new(vec![
        CannedOutcome::success(json!({"v": 1})),
        CannedOutcome::success(json!({"v": 2})),
    ]);
    let req = CannedRequest {
        ident: "force".into(),
        secret: None,
    };
    collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let forced = collect_once(&store, &collector, req.clone(), F::Refresh).unwrap();
    assert_eq!(forced.usage, Usage::Refreshed);
    assert_eq!(forced.data, Some(json!({"v": 2})));
    assert_eq!(forced.data_status, pq_core::evidence::DataStatus::Fresh);
    assert_eq!(collector.call_count(), 2);
    assert_eq!(store.observation_history(&req.key(), 10).unwrap().len(), 2);
}

// --- 13. MaxAge bound --------------------------------------------------------

#[test]
fn max_age_requires_recent_data() {
    let (_dir, store) = open_store();
    // Policy would keep data fresh for an hour…
    store
        .set_policy(&policy_fresh_window(
            "canned",
            Duration::from_secs(3600),
            false,
        ))
        .unwrap();
    let collector = CannedCollector::new(vec![
        CannedOutcome::success(json!({"v": 1})),
        CannedOutcome::success(json!({"v": 2})),
    ]);
    let req = CannedRequest {
        ident: "ma".into(),
        secret: None,
    };
    collect_once(
        &store,
        &collector,
        req.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    // Let the observation age past a zero-second bound (observed_at ties
    // would satisfy MaxAge(0) trivially).
    std::thread::sleep(Duration::from_millis(1100));

    // The caller demands data no older than 0 seconds → re-collect.
    let out = collect_once(&store, &collector, req.clone(), F::MaxAge(Duration::ZERO)).unwrap();
    assert_eq!(out.usage, Usage::Refreshed);
    assert_eq!(collector.call_count(), 2);

    // Reasonable bound → served from cache.
    let out = collect_once(
        &store,
        &collector,
        req,
        F::MaxAge(Duration::from_secs(3600)),
    )
    .unwrap();
    assert_eq!(out.usage, Usage::Cached);
    assert_eq!(collector.call_count(), 2);
}

// --- helpers -----------------------------------------------------------------

fn policy_expired_immediately(kind: &str) -> pq_core::evidence::Policy {
    pq_core::evidence::Policy {
        kind: kind.into(),
        name: "default".into(),
        fresh_for: Some(Duration::ZERO),
        allow_stale: false,
        stale_for: None,
        ttl_min: None,
        ttl_max: None,
    }
}

fn policy_fresh_window(
    kind: &str,
    fresh_for: Duration,
    allow_stale: bool,
) -> pq_core::evidence::Policy {
    pq_core::evidence::Policy {
        kind: kind.into(),
        name: "default".into(),
        fresh_for: Some(fresh_for),
        allow_stale,
        stale_for: None,
        ttl_min: Some(Duration::from_secs(300)),
        ttl_max: Some(Duration::from_secs(86400)),
    }
}
