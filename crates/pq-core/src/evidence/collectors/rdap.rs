//! The RDAP collector: canonical lookup target + provider, original JSON
//! preserved as an artifact, normalized extraction deferred to v2.
//!
//! Provider resolution (IANA bootstrap files) is itself a collection —
//! `rdap-bootstrap`, cached indefinitely — so bootstrap lookups obey the
//! same collect-once discipline.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::Result;
use crate::evidence::http::{HttpExecError, HttpExecutor, HttpMethod, HttpRequest};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use crate::net::normalize_domain;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// Canonical RDAP lookup target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RdapTarget {
    /// In-domain registration data.
    Domain(String),
    /// Address or prefix.
    Ip(String),
    /// Entity handle.
    Entity(String),
}

impl RdapTarget {
    fn path_and_family(&self) -> String {
        match self {
            RdapTarget::Domain(d) => format!(
                "/domain/{}",
                normalize_domain(d).unwrap_or_else(|| d.clone())
            ),
            RdapTarget::Ip(ip) => format!("/ip/{ip}"),
            RdapTarget::Entity(e) => format!("/entity/{}", e.to_ascii_lowercase()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RdapRequest {
    pub target: RdapTarget,
    /// RDAP service base URL. `None` → resolve via IANA bootstrap (a
    /// separate, indefinitely-cached collection).
    pub provider: Option<String>,
}

/// Which IANA bootstrap file serves this target (RFC 9224).
fn bootstrap_file_for(target: &RdapTarget) -> Result<&'static str, CollectionError> {
    match target {
        RdapTarget::Domain(_) => Ok("dns.json"),
        RdapTarget::Ip(ip) => {
            let parsed: std::net::IpAddr = ip.parse().map_err(|_| CollectionError::Error {
                native: None,
                message: format!("bad ip `{ip}`"),
            })?;
            Ok(if parsed.is_ipv6() {
                "ipv6.json"
            } else {
                "ipv4.json"
            })
        }
        RdapTarget::Entity(_) => Ok("entity.json"),
    }
}

/// v1 containment check for bootstrap CIDR entries (e.g. `2001:200::/23`,
/// `1.0.0.0/8`).
fn cidr_contains(cidr: &str, addr: std::net::IpAddr) -> bool {
    let (net, mask) = match cidr.split_once('/') {
        Some(pair) => pair,
        None => return cidr == addr.to_string(),
    };
    let (Ok(net_ip), Ok(mask)) = (net.parse::<std::net::IpAddr>(), mask.parse::<u32>()) else {
        return false;
    };
    match (net_ip, addr) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(a)) => {
            let mask = if mask == 0 {
                0
            } else {
                u32::MAX << (32 - mask)
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(a)) => {
            let mask = if mask == 0 {
                0
            } else {
                u128::MAX << (128 - mask)
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

impl CollectionRequest for RdapRequest {
    const KIND: &'static str = "rdap";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        match &self.target {
            RdapTarget::Domain(d) => {
                w.str_field("target", "domain");
                w.str_field("domain", &d.to_ascii_lowercase());
            }
            RdapTarget::Ip(ip) => {
                w.str_field("target", "ip");
                w.str_field("ip", ip);
            }
            RdapTarget::Entity(e) => {
                w.str_field("target", "entity");
                w.str_field("entity", &e.to_ascii_lowercase());
            }
        }
        w.opt_str_field("provider", self.provider.as_deref());
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "target": self.target, "provider": self.provider })
    }
}

/// IANA RDAP bootstrap collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RdapBootstrapRequest {
    pub family: &'static str,
}

impl CollectionRequest for RdapBootstrapRequest {
    const KIND: &'static str = "rdap-bootstrap";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("family", self.family);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "family": self.family })
    }
}

pub const IANA_BOOTSTRAP_BASE: &str = "https://data.iana.org/rdap/";

/// A parsed IANA bootstrap file: service entries → RDAP base URLs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdapBootstrap {
    pub services: Vec<(Vec<String>, Vec<String>)>, // [cidrs/domains], [base urls]
}

impl RdapBootstrap {
    /// Base URL whose service entry covers `value`, longest match wins
    /// (RFC 9224). Exact match (CIDRs, handles) or dotted-suffix match.
    pub fn base_for(&self, value: &str) -> Option<String> {
        let mut best: Option<(usize, String)> = None;
        for (keys, urls) in &self.services {
            for k in keys {
                let hit = k == value || (k.starts_with('.') && value.ends_with(k));
                if hit && best.as_ref().is_none_or(|(len, _)| k.len() > *len) {
                    if let Some(u) = urls.first() {
                        best = Some((k.len(), u.trim_end_matches('/').to_string()));
                    }
                }
            }
        }
        best.map(|(_, u)| u)
    }
}

/// Bootstrap-file collector (a separate collection identity per family
/// file, cached indefinitely).
pub struct RdapBootstrapCollector {
    pub http: Arc<dyn HttpExecutor>,
}

impl Collector for RdapBootstrapCollector {
    type Request = RdapBootstrapRequest;
    type Output = RdapBootstrap;

    fn collect(
        &self,
        _scan: &Scan,
        req: &RdapBootstrapRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let request = HttpRequest {
            url: format!("{IANA_BOOTSTRAP_BASE}{}", req.family),
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
            timeout: Duration::from_secs(30),
        };
        let response = self.http.execute(&request).map_err(|e| match e {
            HttpExecError::Timeout(d) => CollectionError::Timeout {
                native: Some(format!("timed out after {d:?}")),
            },
            HttpExecError::RateLimited(status) => CollectionError::RateLimited {
                native: Some(status.to_string()),
            },
            other => CollectionError::Error {
                native: None,
                message: other.to_string(),
            },
        })?;
        if response.status != 200 {
            return Err(CollectionError::Error {
                native: Some(response.status.to_string()),
                message: format!("IANA bootstrap returned HTTP {}", response.status),
            });
        }
        // Validate parseability now; the artifact preserves original bytes.
        let parsed: RdapBootstrap =
            serde_json::from_slice(&response.body).map_err(|e| CollectionError::Error {
                native: Some("200".into()),
                message: format!("unparseable bootstrap file: {e}"),
            })?;
        let mut raw = RawObservation::success(serde_json::json!({
            "family": req.family,
            "services": parsed.services.len(),
        }));
        raw.native_status = Some("200".into());
        raw.artifacts.push(RawArtifact {
            role: "rdap_response".into(),
            bytes: response.body,
            content_type: "application/json; role=rdap-bootstrap".into(),
        });
        Ok(raw)
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<RdapBootstrap> {
        let artifact = obs.artifact_by_role("rdap_response").ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!(
                "bootstrap observation {} has no artifact",
                obs.id
            ))
        })?;
        Ok(serde_json::from_slice(&store.read_artifact(artifact)?)?)
    }
}

/// The RDAP collector. Clones share the executor.
#[derive(Clone)]
pub struct RdapCollector {
    pub http: Arc<dyn HttpExecutor>,
}

impl RdapCollector {
    /// Resolve the RDAP service base for `target` through the bootstrap
    /// collection (indefinitely cached; on-read blocking revalidation).
    fn resolve_provider(
        &self,
        scan: &Scan,
        target: &RdapTarget,
    ) -> Result<String, CollectionError> {
        let file = bootstrap_file_for(target)?;
        let req = RdapBootstrapRequest { family: file };
        let collector = RdapBootstrapCollector {
            http: self.http.clone(),
        };
        let outcome = scan
            .collect(
                &collector,
                req,
                crate::evidence::FreshnessRequirement::Cached,
            )
            .map_err(store_to_collection_error)?;
        let observation = outcome.observation.ok_or_else(|| CollectionError::Error {
            native: None,
            message: "IANA bootstrap unavailable".into(),
        })?;
        let artifact = observation
            .artifact_by_role("rdap_response")
            .ok_or_else(|| CollectionError::Error {
                native: None,
                message: "IANA bootstrap has no artifact".into(),
            })?;
        let bytes = scan
            .store()
            .read_artifact(artifact)
            .map_err(store_to_collection_error)?;
        let boot: RdapBootstrap =
            serde_json::from_slice(&bytes).map_err(|e| CollectionError::Error {
                native: None,
                message: format!("bad bootstrap file: {e}"),
            })?;
        let base = match target {
            RdapTarget::Domain(d) => {
                // Longest matching suffix per RFC 9224 (in base_for).
                let d = normalize_domain(d).unwrap_or_else(|| d.clone());
                boot.base_for(&d).ok_or_else(|| CollectionError::NotFound {
                    native: Some("bootstrap".into()),
                })?
            }
            RdapTarget::Ip(ip) => boot
                .base_for(&ip.to_string())
                .or_else(|| {
                    // CIDR entries don't match single addresses by string;
                    // fall back to scanning prefixes.
                    let addr: std::net::IpAddr = ip.parse().ok()?;
                    boot.services
                        .iter()
                        .find(|(cidrs, _)| cidrs.iter().any(|c| cidr_contains(c, addr)))
                        .and_then(|(_, urls)| urls.first())
                        .map(|u| u.trim_end_matches('/').to_string())
                })
                .ok_or_else(|| CollectionError::NotFound {
                    native: Some("bootstrap".into()),
                })?,
            RdapTarget::Entity(_) => boot
                .services
                .first()
                .and_then(|(_, urls)| urls.first())
                .map(|u| u.trim_end_matches('/').to_string())
                .ok_or_else(|| CollectionError::NotFound {
                    native: Some("bootstrap".into()),
                })?,
        };
        Ok(base)
    }
}

fn store_to_collection_error(e: crate::evidence::error::Error) -> CollectionError {
    CollectionError::Error {
        native: None,
        message: e.to_string(),
    }
}

impl Collector for RdapCollector {
    type Request = RdapRequest;
    type Output = Value;

    fn collect(
        &self,
        scan: &Scan,
        req: &RdapRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let provider = match &req.provider {
            Some(p) => p.trim_end_matches('/').to_string(),
            None => self.resolve_provider(scan, &req.target)?,
        };
        let path = req.target.path_and_family();
        let request = HttpRequest {
            url: format!("{provider}{path}"),
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/rdap+json".into())],
            body: None,
            timeout: Duration::from_secs(30),
        };
        let response = self.http.execute(&request).map_err(|e| match e {
            HttpExecError::Timeout(d) => CollectionError::Timeout {
                native: Some(format!("timed out after {d:?}")),
            },
            HttpExecError::RateLimited(status) => CollectionError::RateLimited {
                native: Some(status.to_string()),
            },
            other => CollectionError::Error {
                native: None,
                message: other.to_string(),
            },
        })?;
        match response.status {
            200 => {}
            404 => {
                return Err(CollectionError::NotFound {
                    native: Some("404".into()),
                });
            }
            429 => {
                return Err(CollectionError::RateLimited {
                    native: Some("429".into()),
                });
            }
            other => {
                return Err(CollectionError::Error {
                    native: Some(other.to_string()),
                    message: format!("RDAP returned HTTP {other}"),
                });
            }
        }
        // Validate it is JSON at least shape-wise, preserve original bytes.
        let parsed: Value =
            serde_json::from_slice(&response.body).map_err(|e| CollectionError::Error {
                native: Some("200".into()),
                message: format!("unparseable RDAP JSON: {e}"),
            })?;
        let mut raw = RawObservation::success(serde_json::json!({
            "provider": provider,
            "rdap_type": parsed.get("rdapConformance").cloned().unwrap_or(Value::Null),
        }));
        raw.native_status = Some("200".into());
        raw.artifacts.push(RawArtifact {
            role: "rdap_response".into(),
            bytes: response.body,
            content_type: "application/rdap+json".into(),
        });
        Ok(raw)
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<Value> {
        let artifact = obs.artifact_by_role("rdap_response").ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!(
                "RDAP observation {} has no rdap_response artifact",
                obs.id
            ))
        })?;
        Ok(serde_json::from_slice(&store.read_artifact(artifact)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_matches_longest_suffix() {
        let boot = RdapBootstrap {
            services: vec![
                (
                    vec![".com".into()],
                    vec!["https://rdap.verisign.com/com/v1/".into()],
                ),
                (
                    vec!["example.com".into()],
                    vec!["https://rdap.example-registry.com/".into()],
                ),
            ],
        };
        assert_eq!(
            boot.base_for("example.com").unwrap(),
            "https://rdap.example-registry.com"
        );
        assert_eq!(
            boot.base_for("other.com").unwrap(),
            "https://rdap.verisign.com/com/v1"
        );
        assert!(boot.base_for("example.org").is_none());
    }

    #[test]
    fn target_paths_are_canonical() {
        assert_eq!(
            RdapTarget::Domain("EXAMPLE.com".into()).path_and_family(),
            "/domain/example.com"
        );
        assert_eq!(
            RdapTarget::Ip("2001:db8::1".into()).path_and_family(),
            "/ip/2001:db8::1"
        );
    }
}
