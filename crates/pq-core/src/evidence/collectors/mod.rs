//! The v1 collectors: every collection path that exists across the pq-intel
//! tools, unified over the evidence store.
//!
//! Production transports (ureq HTTP, std UDP/TCP DNS via hickory-proto
//! wire-format, rustls TLS) live beside the traits they implement, so tests
//! run the same collectors against canned transports.

pub mod asn;
pub mod ct;
pub mod ctdb;
pub mod dns;
pub mod dns_transport;
pub mod http_collector;
#[cfg(feature = "openssl-tls")]
pub mod openssl_tls;
pub mod ports;
pub mod rdap;
pub mod ripestat;
pub mod tls;
pub mod tls_connector;

use crate::evidence::observation::{ObservationStatus, RawObservation, StoredObservation};

/// The refusal answer: a completed capture recording definitive endpoint
/// absence ("nothing listens here"). Shared by the tls and http collectors
/// so every refused connect reads the same across kinds.
pub(crate) fn closed_observation(native: &str, endpoint: &str) -> RawObservation {
    RawObservation {
        status: ObservationStatus::NotFound,
        native_status: Some(native.into()),
        source_time: None,
        metadata: serde_json::json!({ "reason": "connection_refused", "endpoint": endpoint }),
        artifacts: Vec::new(),
        fresh_hint: None,
        policy_name: None,
        confirms: None,
    }
}

/// Whether a stored observation is a refusal answer ([`closed_observation`]):
/// a not_found with the refusal reason. Refusals carry no response, so the
/// collectors' decodes treat their missing artifacts as the answer's shape,
/// not corruption.
pub(crate) fn is_closed_observation(obs: &StoredObservation) -> bool {
    use crate::evidence::observation::ObservationStatus;
    obs.status == ObservationStatus::NotFound
        && obs.metadata.get("reason").and_then(|v| v.as_str()) == Some("connection_refused")
}
