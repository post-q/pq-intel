//! The ASN capture: IP registration facts (origin ASN, org, netname) per
//! canonical IP, from the RIPEstat `network-info` endpoint.
//!
//! A distinct capture kind (`asn`) so the fleet's tasking vocabulary, its
//! per-kind freshness facts, and this collection's identity line up
//! one-to-one. Identity is the IP alone — one registration lookup serves
//! every hostname that resolves to the same IP (the ripestat collector's
//! identity rule, renamed for the capture plane). The trigger is the DNS
//! fact, never the connection: collectors downstream consume what the store
//! already holds.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::collectors::ripestat::{RipestatCollector, RipestatRequest};
use crate::evidence::error::Result;
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use serde_json::Value;
use std::borrow::Cow;

/// ASN capture request: the canonical resource is the IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnRequest {
    /// Canonical resource: the IP address (v4 or v6) as text.
    pub resource: String,
}

impl AsnRequest {
    pub fn current(ip: &str) -> Self {
        Self {
            resource: ip.to_string(),
        }
    }
}

impl CollectionRequest for AsnRequest {
    const KIND: &'static str = "asn";
    fn policy_name(&self) -> Cow<'static, str> {
        Cow::Borrowed("network-info")
    }
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("resource", &self.resource);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "endpoint": "network-info", "resource": self.resource })
    }
}

/// The ASN collector: the RIPEstat data API pinned to `network-info`.
#[derive(Clone)]
pub struct AsnCollector {
    pub inner: RipestatCollector,
}

impl Collector for AsnCollector {
    type Request = AsnRequest;
    type Output = Value;

    fn collect(
        &self,
        scan: &Scan,
        req: &AsnRequest,
        prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        self.inner.collect(
            scan,
            &RipestatRequest::current("network-info", &req.resource),
            prior,
        )
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<Value> {
        self.inner.decode(store, obs)
    }

    fn policy_name(
        &self,
        _req: &AsnRequest,
        _latest_status: Option<crate::evidence::observation::ObservationStatus>,
    ) -> std::borrow::Cow<'static, str> {
        Cow::Borrowed("network-info")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_of(ip: &str) -> String {
        AsnRequest::current(ip).key().hex()
    }

    #[test]
    fn identity_is_the_ip_and_the_kind_is_asn() {
        // Same IP: one collection. Different IP: different collection.
        assert_eq!(key_of("34.79.168.106"), key_of("34.79.168.106"));
        assert_ne!(key_of("34.79.168.106"), key_of("172.65.238.9"));
        // A distinct kind from the generic ripestat collector, so per-kind
        // freshness facts and policies never cross.
        assert_eq!(AsnRequest::KIND, "asn");
        assert_ne!(AsnRequest::KIND, RipestatRequest::KIND);
    }

    #[test]
    fn policy_is_the_registration_shaped_network_info() {
        let req = AsnRequest::current("34.79.168.106");
        assert_eq!(CollectionRequest::policy_name(&req), "network-info");
    }
}
