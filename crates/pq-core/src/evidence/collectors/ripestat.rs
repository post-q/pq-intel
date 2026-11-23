//! The RIPEstat collector: per-endpoint collection identities
//! (`network-info`, `routing-status`, ...) with per-endpoint policies;
//! historical (finalized-interval) queries cached indefinitely.
//!
//! Identity is endpoint + resource + parameters (+ query time). Because the
//! resource is the canonical IP/prefix/ASN, one registration lookup serves
//! every hostname that resolves to the same IP.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::Result;
use crate::evidence::http::{HttpExecError, HttpExecutor, HttpMethod, HttpRequest};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RipestatRequest {
    /// Data API endpoint id, e.g. `network-info`, `routing-status`.
    pub endpoint: String,
    /// Canonical resource: IP address, prefix, or ASN (`AS1234`).
    pub resource: String,
    /// Additional query parameters (order-insensitive identity).
    pub params: BTreeMap<String, String>,
    /// Query time for finalized-interval (historical) queries — cached
    /// indefinitely. `None` = current state, per-endpoint policy.
    pub query_time: Option<DateTime<Utc>>,
}

impl RipestatRequest {
    pub fn current(endpoint: &str, resource: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            resource: resource.to_string(),
            params: BTreeMap::new(),
            query_time: None,
        }
    }
}

impl CollectionRequest for RipestatRequest {
    const KIND: &'static str = "ripestat";
    fn policy_name(&self) -> std::borrow::Cow<'static, str> {
        if self.query_time.is_some() {
            std::borrow::Cow::Borrowed("historical")
        } else {
            std::borrow::Cow::Owned(self.endpoint.clone())
        }
    }
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("endpoint", &self.endpoint);
        w.str_field("resource", &self.resource);
        w.pair_list_field(
            "params",
            &self
                .params
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
        );
        match self.query_time {
            Some(t) => w.str_field("query_time", &t.to_rfc3339()),
            None => w.opt_str_field("query_time", None),
        }
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoint": self.endpoint,
            "resource": self.resource,
            "params": self.params,
            "query_time": self.query_time.map(|t| t.to_rfc3339()),
        })
    }
}

pub const RIPESTAT_DATA_URL: &str = "https://stat.ripe.net/data/";

/// The RIPEstat collector. Clones share the executor.
#[derive(Clone)]
pub struct RipestatCollector {
    pub http: Arc<dyn HttpExecutor>,
}

impl Collector for RipestatCollector {
    type Request = RipestatRequest;
    type Output = Value;

    fn collect(
        &self,
        _scan: &Scan,
        req: &RipestatRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let mut params: Vec<(&str, String)> = vec![("resource", req.resource.clone())];
        if let Some(t) = req.query_time {
            params.push((
                "querytime",
                t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ));
        }
        for (k, v) in &req.params {
            params.push((k.as_str(), v.clone()));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params)
            .finish();
        let request = HttpRequest {
            url: format!("{RIPESTAT_DATA_URL}{}/data.json?{}", req.endpoint, query),
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
                message: format!("RIPEstat returned HTTP {}", response.status),
            });
        }
        let parsed: Value =
            serde_json::from_slice(&response.body).map_err(|e| CollectionError::Error {
                native: Some("200".into()),
                message: format!("unparseable RIPEstat JSON: {e}"),
            })?;
        // The data API reports errors inside HTTP 200.
        let api_status = parsed
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("ok");
        let currenttime = parsed
            .get("currenttime")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let mut raw = RawObservation::success(serde_json::json!({
            "endpoint": req.endpoint,
            "api_status": api_status,
            "currenttime": currenttime,
        }));
        raw.source_time = currenttime
            .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.into());
        if api_status == "error" {
            raw.status = crate::evidence::observation::ObservationStatus::Error;
            raw.native_status = Some("ripestat:error".into());
        } else {
            raw.native_status = Some("200".into());
        }
        raw.artifacts.push(RawArtifact {
            role: "ripestat_response".into(),
            bytes: response.body,
            content_type: "application/json; role=ripestat-response".into(),
        });
        Ok(raw)
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<Value> {
        let artifact = obs.artifact_by_role("ripestat_response").ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!(
                "RIPEstat observation {} has no artifact",
                obs.id
            ))
        })?;
        let full: Value = serde_json::from_slice(&store.read_artifact(artifact)?)?;
        Ok(full.get("data").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_queries_use_the_historical_policy() {
        let current = RipestatRequest::current("network-info", "193.0.6.1");
        assert_eq!(CollectionRequest::policy_name(&current), "network-info");
        let historical = RipestatRequest {
            query_time: Some(Utc::now()),
            ..current
        };
        assert_eq!(CollectionRequest::policy_name(&historical), "historical");
    }

    #[test]
    fn same_ip_different_hostnames_share_identity() {
        // Hostname-level detail never enters the key: the resource is the IP.
        let a = RipestatRequest::current("network-info", "193.0.6.1");
        let b = RipestatRequest::current("network-info", "193.0.6.1");
        assert_eq!(a.key(), b.key());
        let c = RipestatRequest::current("routing-status", "193.0.6.1");
        assert_ne!(
            a.key(),
            c.key(),
            "different endpoints are different collections"
        );
    }
}
