//! Collectors: the unified definition of every collection path the pq-intel
//! tools use (DNS, DoH, HTTP, TLS, CT, RDAP, RIPEstat).
//!
//! A collector owns three things:
//! 1. the canonical identity of its requests ([`CollectionRequest`]),
//! 2. the network collection itself ([`Collector::collect`], behind
//!    transport seams so tests run canned, offline),
//! 3. decoding a stored observation back into its typed output
//!    ([`Collector::decode`]) — the same path cached and fresh data take.
//!
//! The store's [`Scan::collect`](crate::evidence::scan::Scan::collect) driver
//! wraps these with freshness evaluation, single-flight, provenance, artifact
//! persistence, and scan usage recording.

use crate::evidence::error::Result;
use crate::evidence::key::CollectionRequest;
use crate::evidence::observation::{ObservationStatus, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use std::borrow::Cow;

/// A collection-level failure. The driver persists it as an observation with
/// the corresponding status — a failed collection never erases the last
/// successful result, and a timeout is recorded as "unknown", never as
/// "nonexistent".
#[derive(Debug, thiserror::Error)]
pub enum CollectionError {
    #[error("not found: {native:?}")]
    NotFound { native: Option<String> },
    #[error("timeout: {native:?}")]
    Timeout { native: Option<String> },
    #[error("rate limited: {native:?}")]
    RateLimited { native: Option<String> },
    #[error("{message} (native: {native:?})")]
    Error {
        native: Option<String>,
        message: String,
    },
}

impl CollectionError {
    pub fn status(&self) -> ObservationStatus {
        match self {
            CollectionError::NotFound { .. } => ObservationStatus::NotFound,
            CollectionError::Timeout { .. } => ObservationStatus::Timeout,
            CollectionError::RateLimited { .. } => ObservationStatus::RateLimited,
            CollectionError::Error { .. } => ObservationStatus::Error,
        }
    }

    pub fn native(&self) -> Option<&str> {
        match self {
            CollectionError::NotFound { native }
            | CollectionError::Timeout { native }
            | CollectionError::RateLimited { native } => native.as_deref(),
            CollectionError::Error { native, .. } => native.as_deref(),
        }
    }

    /// Failure observation body: no artifacts, message recorded in metadata.
    pub fn to_raw(&self) -> RawObservation {
        let mut raw = RawObservation::success(serde_json::json!({
            "error": self.to_string(),
        }));
        raw.status = self.status();
        raw.native_status = self.native().map(str::to_owned);
        raw
    }
}

pub trait Collector: Send + Sync {
    type Request: CollectionRequest;
    /// Typed view of the collected/cached data, decoded from the stored
    /// observation (and its artifacts).
    type Output;

    /// Run the collection. `prior` is the last usable stored observation for
    /// this collection identity, if any — collectors use it for conditional
    /// revalidation (HTTP `If-None-Match`/`If-Modified-Since`).
    ///
    /// Store-level infrastructure failures (artifact IO, sqlite) surface as
    /// `Err(crate::evidence::error::Error)`; collection-level outcomes —
    /// including failures like timeouts and rcodes — return `Ok(RawObservation)`
    /// with the appropriate status.
    fn collect(
        &self,
        scan: &Scan,
        req: &Self::Request,
        prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError>;

    /// Decode a stored observation into the typed output. Called for cached,
    /// refreshed, and historical reads alike.
    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<Self::Output>;

    /// Policy name for evaluation, refinable per outcome (e.g. the DNS
    /// collector routes negative answers to the `negative` policy when the
    /// latest stored answer is a `not_found`).
    fn policy_name(
        &self,
        _req: &Self::Request,
        _latest_status: Option<ObservationStatus>,
    ) -> Cow<'static, str> {
        Cow::Borrowed("default")
    }
}
