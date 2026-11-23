//! The TLS collector: one definition of a TLS observation for all tools.
//!
//! Endpoint-targeted (host, port, SNI, ALPN, client config — all part of the
//! collection key). Preserves protocol version, cipher suite, key exchange
//! group, negotiated ALPN, and the served chain (leaf + intermediates as
//! certificate artifacts). Replaces both tools' private TLS result formats:
//! `pq-map`'s `Negotiated`/`ServedCert` and `pq-pulse`'s `TlsSession` both
//! become views over this observation.

use super::tls_connector::{TlsConnectError, TlsConnector, TlsEndpoint, TlsSessionFacts};
use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::Result;
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use crate::net::normalize_domain;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The decoded TLS observation: session facts with the chain re-read from
/// artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsObservation {
    pub session: TlsSessionFacts,
}

/// Pure mapping: TLS session state → raw observation. Unit-tested directly
/// (spec seam 3): no store, no connector.
pub fn session_to_observation(
    endpoint_host: &str,
    endpoint_port: u16,
    facts: &TlsSessionFacts,
) -> RawObservation {
    let mut raw = RawObservation::success(serde_json::json!({
        "endpoint": format!("{endpoint_host}:{endpoint_port}"),
        "protocol_version": facts.protocol_version,
        "cipher_suite": facts.cipher_suite,
        "kex_group": facts.kex_group,
        "alpn": facts.alpn_negotiated,
        "sni": facts.sni_used,
        "chain_len": facts.chain.len(),
    }));
    raw.native_status = Some(format!("tls:{}", facts.protocol_version));
    let mut chain = facts.chain.iter();
    if let Some(leaf) = chain.next() {
        raw.artifacts.push(RawArtifact {
            role: "leaf_certificate".into(),
            bytes: leaf.clone(),
            content_type: "application/x-x509-certificate; encoding=der".into(),
        });
    }
    for intermediate in chain {
        raw.artifacts.push(RawArtifact {
            role: "intermediate_certificate".into(),
            bytes: intermediate.clone(),
            content_type: "application/x-x509-certificate; encoding=der".into(),
        });
    }
    raw
}

/// The TLS collector. Clones share the connector.
#[derive(Clone)]
pub struct TlsCollector {
    pub connector: Arc<dyn TlsConnector>,
}

impl Collector for TlsCollector {
    type Request = TlsRequest;
    type Output = TlsObservation;

    fn collect(
        &self,
        _scan: &Scan,
        req: &TlsRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let facts = self
            .connector
            .connect(&req.endpoint)
            .map_err(map_connect_error)?;
        Ok(session_to_observation(
            &req.endpoint.host,
            req.endpoint.port,
            &facts,
        ))
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<TlsObservation> {
        let leaf = obs
            .artifact_by_role("leaf_certificate")
            .map(|meta| store.read_artifact(meta))
            .transpose()?;
        let intermediates: Vec<Vec<u8>> = obs
            .artifacts
            .iter()
            .filter(|l| l.role == "intermediate_certificate")
            .map(|l| store.read_artifact(&l.artifact))
            .collect::<Result<_>>()?;
        let mut session = session_from_metadata(&obs.metadata)?;
        session.chain = leaf.into_iter().chain(intermediates).collect();
        Ok(TlsObservation { session })
    }
}

/// Typed view over the stored metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMetadata {
    pub endpoint: String,
    pub protocol_version: String,
    pub cipher_suite: String,
    pub kex_group: String,
    pub alpn: Option<String>,
    pub sni: String,
    pub chain_len: usize,
}

pub fn session_from_metadata(metadata: &serde_json::Value) -> Result<TlsSessionFacts> {
    let meta: TlsMetadata = serde_json::from_value(metadata.clone())?;
    Ok(TlsSessionFacts {
        protocol_version: meta.protocol_version,
        cipher_suite: meta.cipher_suite,
        kex_group: meta.kex_group,
        alpn_negotiated: meta.alpn,
        sni_used: meta.sni,
        chain: vec![],
    })
}

fn map_connect_error(e: TlsConnectError) -> CollectionError {
    match e {
        TlsConnectError::Timeout(d) => CollectionError::Timeout {
            native: Some(format!("timed out after {d:?}")),
        },
        // A failed DNS resolution of the target is "unknown" (the DNS
        // collector records the actual state as its own observation), never
        // "nonexistent".
        TlsConnectError::Dns(m) => CollectionError::Error {
            native: Some("dns:unresolved".into()),
            message: m,
        },
        TlsConnectError::Connection(m) => CollectionError::Error {
            native: Some("tls:connection".into()),
            message: m,
        },
        TlsConnectError::Handshake { alert, message } => CollectionError::Error {
            native: Some("tls:handshake".into()),
            message: format!("{message} (alert: {alert:?})"),
        },
    }
}

/// TLS collection request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsRequest {
    pub endpoint: TlsEndpoint,
}

impl TlsRequest {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        let host = normalize_domain(host).ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!("invalid host `{host}`"))
        })?;
        Ok(Self {
            endpoint: TlsEndpoint {
                host,
                port,
                sni: None,
                alpn: vec![],
                client_config: DEFAULT_TLS_CLIENT_CONFIG.to_string(),
            },
        })
    }

    pub fn with_alpn(mut self, alpn: &[&str]) -> Self {
        self.endpoint.alpn = alpn.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Identity of the default client configuration shipped with pq-core:
/// rustls + aws-lc-rs, PQ kex preferred, all protocol versions enabled that
/// rustls supports. Bump when the default client behavior changes so old
/// observations keep their identity.
pub const DEFAULT_TLS_CLIENT_CONFIG: &str = "rustls-0.23-aws-lc-rs-pq-preferred-v1";

impl CollectionRequest for TlsRequest {
    const KIND: &'static str = "tls";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("host", &self.endpoint.host);
        w.u16_field("port", self.endpoint.port);
        w.opt_str_field("sni", self.endpoint.sni.as_deref());
        w.str_list_field("alpn", &self.endpoint.alpn);
        w.str_field("client_config", &self.endpoint.client_config);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({
            "host": self.endpoint.host,
            "port": self.endpoint.port,
            "sni": self.endpoint.sni,
            "alpn": self.endpoint.alpn,
            "client_config": self.endpoint.client_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> TlsSessionFacts {
        TlsSessionFacts {
            protocol_version: "TLS 1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            kex_group: "X25519MLKEM768".into(),
            alpn_negotiated: Some("h2".into()),
            sni_used: "example.com".into(),
            chain: vec![b"leaf-der".to_vec(), b"inter-der".to_vec()],
        }
    }

    #[test]
    fn session_maps_to_observation_with_roles() {
        let raw = session_to_observation("example.com", 443, &facts());
        assert_eq!(
            raw.status,
            crate::evidence::observation::ObservationStatus::Success
        );
        assert_eq!(raw.native_status.as_deref(), Some("tls:TLS 1.3"));
        assert_eq!(raw.metadata["kex_group"], "X25519MLKEM768");
        assert_eq!(raw.metadata["endpoint"], "example.com:443");
        assert_eq!(raw.artifacts.len(), 2);
        assert_eq!(raw.artifacts[0].role, "leaf_certificate");
        assert_eq!(raw.artifacts[0].bytes, b"leaf-der");
        assert_eq!(raw.artifacts[1].role, "intermediate_certificate");
        assert_eq!(raw.artifacts[1].bytes, b"inter-der");
    }

    #[test]
    fn chainless_session_maps_without_artifacts() {
        let mut f = facts();
        f.chain.clear();
        let raw = session_to_observation("example.com", 443, &f);
        assert!(raw.artifacts.is_empty());
        assert_eq!(raw.metadata["chain_len"], 0);
    }

    #[test]
    fn differing_sni_or_alpn_differ_in_identity() {
        let base = TlsRequest::new("example.com", 443).unwrap();
        let with_alpn = TlsRequest::new("example.com", 443)
            .unwrap()
            .with_alpn(&["h2"]);
        let other_sni = TlsRequest {
            endpoint: TlsEndpoint {
                host: "example.com".into(),
                port: 443,
                sni: Some("other.example.com".into()),
                alpn: vec![],
                client_config: DEFAULT_TLS_CLIENT_CONFIG.into(),
            },
        };
        assert_ne!(base.key(), with_alpn.key(), "ALPN is part of the key");
        assert_ne!(base.key(), other_sni.key(), "SNI is part of the key");
    }
}
