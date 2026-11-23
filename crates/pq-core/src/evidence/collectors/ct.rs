//! The CT (Certificate Transparency) collector.
//!
//! v1: the crt.sh HTTP fallback (JSON API) runs through the shared HTTP
//! executor; the Postgres read path (pq-map's tokio-postgres session)
//! stays thin where it lives and maps its rows through
//! [`ct_rows_to_raw_observation`] — one pure row→observation mapping for
//! both sources. CT results are cached indefinitely (policy default).
//!
//! The full result set is bulk evidence: the original JSON is preserved as
//! an artifact; the observation metadata carries only the count and newest
//! entry timestamp.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::Result;
use crate::evidence::http::{HttpExecError, HttpExecutor, HttpMethod, HttpRequest};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use crate::net::normalize_domain;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// One crt.sh certwatch row (JSON API and Postgres shapes unified; fields
/// the sources don't share are `Option`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtShRow {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub issuer_ca_id: Option<i64>,
    #[serde(default)]
    pub issuer_name: Option<String>,
    /// SANs/CN as given; newline-separated for multi-name certificates.
    #[serde(default)]
    pub name_value: Option<String>,
    #[serde(default)]
    pub common_name: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    /// Hex serial (crt.sh `serial_number`); needed to dedup rows and to
    /// correlate with live probes.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// When the row entered the log (crt.sh `min_entry_timestamp`).
    #[serde(default)]
    pub min_entry_timestamp: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtRequest {
    /// Query subject: a domain, or a crt.sh query expression (e.g.
    /// `%.example.com` for suffix match).
    pub subject: String,
    /// Exclude expired certificates.
    pub exclude_expired: bool,
}

impl CtRequest {
    pub fn domain(name: &str) -> Result<Self> {
        let subject = normalize_domain(name).ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!("invalid CT subject `{name}`"))
        })?;
        Ok(Self {
            subject,
            exclude_expired: true,
        })
    }
}

impl CollectionRequest for CtRequest {
    const KIND: &'static str = "ct";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("subject", &self.subject);
        w.bool_field("exclude_expired", self.exclude_expired);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "subject": self.subject, "exclude_expired": self.exclude_expired })
    }
}

/// Pure mapping: certwatch rows → raw observation (shared by the Postgres
/// read path and the HTTP fallback).
pub fn ct_rows_to_raw_observation(rows: &[CtShRow]) -> Result<RawObservation> {
    let newest_entry: Option<&String> = rows
        .iter()
        .filter_map(|r| r.min_entry_timestamp.as_ref())
        .max();
    let mut raw = RawObservation::success(serde_json::json!({
        "count": rows.len(),
        "newest_entry": newest_entry,
    }));
    raw.source_time = newest_entry
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|t| t.into());
    raw.artifacts.push(RawArtifact {
        role: "ct_response".into(),
        bytes: serde_json::to_vec(rows)?,
        content_type: "application/json; role=ct-rows".into(),
    });
    Ok(raw)
}

/// The CT collector. Clones share the executor.
#[derive(Clone)]
pub struct CtCollector {
    pub http: Arc<dyn HttpExecutor>,
}

/// crt.sh JSON endpoint (the HTTP fallback path).
pub const CRT_SH_JSON_URL: &str = "https://crt.sh/";

impl Collector for CtCollector {
    type Request = CtRequest;
    type Output = Vec<CtShRow>;

    fn collect(
        &self,
        _scan: &Scan,
        req: &CtRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let mut query = vec![("q", req.subject.clone()), ("output", "json".to_string())];
        if req.exclude_expired {
            query.push(("exclude", "expired".to_string()));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query)
            .finish();
        let request = HttpRequest {
            url: format!("{CRT_SH_JSON_URL}?{query}"),
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
            timeout: Duration::from_secs(60),
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
                    message: format!("crt.sh returned HTTP {other}"),
                });
            }
        }
        let rows: Vec<CtShRow> =
            serde_json::from_slice(&response.body).map_err(|e| CollectionError::Error {
                native: Some("200".into()),
                message: format!("unparseable crt.sh JSON: {e}"),
            })?;
        ct_rows_to_raw_observation(&rows).map_err(|e| match e {
            crate::evidence::error::Error::Json(_) => CollectionError::Error {
                native: None,
                message: e.to_string(),
            },
            other => CollectionError::Error {
                native: None,
                message: other.to_string(),
            },
        })
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<Vec<CtShRow>> {
        let artifact = obs.artifact_by_role("ct_response").ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!(
                "CT observation {} has no ct_response artifact",
                obs.id
            ))
        })?;
        let rows: Vec<CtShRow> = serde_json::from_slice(&store.read_artifact(artifact)?)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, names: &str, ts: &str) -> CtShRow {
        CtShRow {
            id: Some(id),
            issuer_ca_id: Some(42),
            issuer_name: Some("Test CA".into()),
            name_value: Some(names.into()),
            common_name: Some("example.com".into()),
            not_before: Some("2026-01-01T00:00:00".into()),
            not_after: Some("2027-01-01T00:00:00".into()),
            serial_number: Some("0a1b".into()),
            min_entry_timestamp: Some(ts.into()),
            cert: None,
        }
    }

    #[test]
    fn rows_map_to_observation_with_artifact_and_source_time() {
        let rows = vec![
            row(1, "example.com\nwww.example.com", "2026-11-20T00:00:00Z"),
            row(2, "example.com", "2026-11-21T00:00:00Z"),
        ];
        let raw = ct_rows_to_raw_observation(&rows).unwrap();
        assert_eq!(
            raw.status,
            crate::evidence::observation::ObservationStatus::Success
        );
        assert_eq!(raw.metadata["count"], 2);
        assert_eq!(raw.metadata["newest_entry"], "2026-11-21T00:00:00Z");
        assert_eq!(
            raw.source_time.unwrap().timestamp(),
            chrono::DateTime::parse_from_rfc3339("2026-11-21T00:00:00Z")
                .unwrap()
                .timestamp()
        );
        let artifact = &raw.artifacts[0];
        assert_eq!(artifact.role, "ct_response");
        let back: Vec<CtShRow> = serde_json::from_slice(&artifact.bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(
            back[0].name_value.as_deref(),
            Some("example.com\nwww.example.com")
        );
    }

    #[test]
    fn empty_result_set_is_a_valid_positive_answer() {
        let raw = ct_rows_to_raw_observation(&[]).unwrap();
        assert_eq!(raw.metadata["count"], 0);
        assert_eq!(
            raw.status,
            crate::evidence::observation::ObservationStatus::Success
        );
        assert!(raw.source_time.is_none());
    }
}
