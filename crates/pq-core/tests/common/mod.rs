//! Shared helpers for the store-API integration tests (tier 2): a canned
//! collector driven by scripted outcomes — no network, real SQLite.

use pq_core::evidence::collector::{CollectionError, Collector};
use pq_core::evidence::error::Result;
use pq_core::evidence::key::{CanonicalWriter, CollectionKey, CollectionRequest};
use pq_core::evidence::observation::{
    ObservationStatus, RawArtifact, RawObservation, StoredObservation,
};
use pq_core::evidence::scan::{Collected, Scan};
use pq_core::evidence::store::Store;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Scripted request: identity is the string; `secret` participates in
/// equality of the REQUEST but never in the canonical key (it is never read
/// back — that is the invariant).
#[derive(Clone)]
pub struct CannedRequest {
    pub ident: String,
    #[allow(dead_code)]
    pub secret: Option<String>,
}

impl CollectionRequest for CannedRequest {
    const KIND: &'static str = "canned";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("ident", &self.ident);
        // secret deliberately omitted
    }
    fn stored_params(&self) -> Value {
        json!({ "ident": self.ident })
    }
}

/// What the canned collector does on each collect() call.
#[allow(dead_code)]
pub enum CannedOutcome {
    Success {
        native: Option<String>,
        metadata: Value,
        artifacts: Vec<(&'static str, Vec<u8>, &'static str)>,
        fresh_hint: Option<std::time::Duration>,
        source_time: Option<chrono::DateTime<chrono::Utc>>,
    },
    #[allow(dead_code)]
    Fail(CollectionError),
}

#[allow(dead_code)]
impl CannedOutcome {
    pub fn success(metadata: Value) -> Self {
        Self::Success {
            native: None,
            metadata,
            artifacts: vec![],
            fresh_hint: None,
            source_time: None,
        }
    }
}

/// A collector whose behavior is a script of outcomes. Records the requests
/// it saw.
#[allow(dead_code)]
pub struct CannedCollector {
    script: Mutex<Vec<CannedOutcome>>,
    pub calls: Mutex<Vec<CannedRequest>>,
    /// Optional gate: while true, collect() spins — tests flip it to false
    /// to let the leader proceed.
    pub gate: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl CannedCollector {
    #[allow(dead_code)]
    pub fn new(script: Vec<CannedOutcome>) -> Self {
        Self {
            script: Mutex::new(script),
            calls: Mutex::new(vec![]),
            gate: None,
        }
    }

    /// A collector whose collect() blocks (spinning) until the gate is
    /// flipped to false.
    #[allow(dead_code)]
    pub fn gated(script: Vec<CannedOutcome>, gate: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            script: Mutex::new(script),
            calls: Mutex::new(vec![]),
            gate: Some(gate),
        }
    }

    #[allow(dead_code)]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Collector for CannedCollector {
    type Request = CannedRequest;
    type Output = Value;

    fn collect(
        &self,
        _scan: &Scan,
        req: &CannedRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        self.calls.lock().unwrap().push(req.clone());
        if let Some(gate) = &self.gate {
            while gate.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::yield_now();
            }
        }
        let outcome = {
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                panic!("canned collector script exhausted");
            }
            script.drain(..1).next().unwrap()
        };
        match outcome {
            CannedOutcome::Success {
                native,
                metadata,
                artifacts,
                fresh_hint,
                source_time,
            } => {
                let mut raw = RawObservation::success(metadata);
                raw.native_status = native;
                raw.fresh_hint = fresh_hint;
                raw.source_time = source_time;
                raw.artifacts = artifacts
                    .into_iter()
                    .map(|(role, bytes, ct)| RawArtifact {
                        role: role.into(),
                        bytes,
                        content_type: ct.into(),
                    })
                    .collect();
                Ok(raw)
            }
            CannedOutcome::Fail(e) => Err(e),
        }
    }

    fn decode(&self, _store: &Store, obs: &StoredObservation) -> Result<Value> {
        Ok(obs.metadata.clone())
    }
}

#[allow(dead_code)] // unused in test crates that only import specific helpers
pub fn open_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    // The `canned` kind has no seeded default; tests install one through the
    // public API (policies are data).
    store
        .set_policy(&pq_core::evidence::Policy {
            kind: "canned".into(),
            name: "default".into(),
            fresh_for: Some(Duration::from_secs(3600)),
            allow_stale: false,
            stale_for: None,
            ttl_min: None,
            ttl_max: None,
        })
        .unwrap();
    (dir, store)
}

/// Shorthand: run one collection in a fresh scan.
#[allow(dead_code)]
pub fn collect_once<C: Collector>(
    store: &Store,
    collector: &C,
    req: C::Request,
    freshness: pq_core::evidence::FreshnessRequirement,
) -> Result<Collected<C::Output>> {
    let scan = store.begin_scan("test-tool", json!({}))?;
    let out = scan.collect(collector, req, freshness)?;
    scan.finish()?;
    Ok(out)
}

#[allow(dead_code)]
pub fn timeout_err() -> CollectionError {
    CollectionError::Timeout {
        native: Some("connection timed out".into()),
    }
}

#[allow(dead_code)]
pub fn obs_status(obs: &StoredObservation) -> ObservationStatus {
    obs.status
}

#[allow(dead_code)]
pub fn key_of(req: &CannedRequest) -> CollectionKey {
    req.key()
}
