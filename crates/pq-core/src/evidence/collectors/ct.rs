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
use chrono::{DateTime, Utc};
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
    raw.source_time = newest_entry.and_then(|ts| ctdate(ts));
    raw.artifacts.push(RawArtifact {
        role: "ct_response".into(),
        bytes: serde_json::to_vec(rows)?,
        content_type: "application/json; role=ct-rows".into(),
    });
    Ok(raw)
}

// Certwatch row semantics shared by every consumer of crt.sh data (this
// collector, pq-map's model mapping, downstream analysis): timestamp
// repair, name-list handling, RFC 6125 coverage, serial normalization,
// and jq-epoch validity. One definition per external quirk.

/// Where a certificate matches a host: exact name equality or an RFC 6125
/// single-label wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Wildcard,
}

/// crt.sh timestamps carry no zone ("2014-04-23T12:16:09"); RFC 3339
/// requires one. jq's fromdateiso8601 also accepts compact offsets
/// (+0200); chrono needs +02:00. The certwatch DB ::text shape is naive.
pub fn ctdate(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_t = raw.replace(' ', "T");
    let with_zone = if has_explicit_zone(&with_t) {
        normalize_zone(with_t)
    } else {
        format!("{with_t}Z")
    };
    DateTime::parse_from_rfc3339(&with_zone)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// +HHMM → +HH:MM so that RFC 3339 parsing succeeds.
fn normalize_zone(s: String) -> String {
    let b = s.as_bytes();
    if b.len() >= 5 {
        let tail = &b[b.len() - 5..];
        if (tail[0] == b'+' || tail[0] == b'-') && tail[1..].iter().all(u8::is_ascii_digit) {
            return format!(
                "{}{}:{}",
                &s[..s.len() - 5],
                &s[s.len() - 5..s.len() - 2],
                &s[s.len() - 2..]
            );
        }
    }
    s
}

fn has_explicit_zone(s: &str) -> bool {
    let b = s.as_bytes();
    if b.ends_with(b"Z") || b.ends_with(b"z") {
        return true;
    }
    // +HH:MM (6 bytes) or +HHMM (5 bytes)
    let check = |len: usize| -> bool {
        if b.len() < len {
            return false;
        }
        let t = &b[b.len() - len..];
        if t[0] != b'+' && t[0] != b'-' {
            return false;
        }
        let rest = &t[1..];
        match len {
            6 => {
                rest[0].is_ascii_digit()
                    && rest[1].is_ascii_digit()
                    && rest[2] == b':'
                    && rest[3].is_ascii_digit()
                    && rest[4].is_ascii_digit()
            }
            5 => rest.iter().all(u8::is_ascii_digit),
            _ => false,
        }
    };
    check(6) || check(5)
}

/// SANs/CN of a `name_value` row: split, lowercased, sorted, deduped.
pub fn names(name_value: &str) -> Vec<String> {
    let mut out: Vec<String> = name_value
        .split('\n')
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn is_wildcard(name: &str) -> bool {
    name.starts_with("*.")
}

/// RFC 6125 single-label wildcard: `*.base` covers `x.base` only - not `a.b.base`, not `base`.
pub fn coverage(identities: &[String], host: &str) -> Option<MatchKind> {
    if identities.iter().any(|n| n == host) {
        return Some(MatchKind::Exact);
    }
    for n in identities {
        if let Some(base) = n.strip_prefix("*.") {
            let host_labels = host.split('.').count();
            let base_labels = base.split('.').count();
            if host_labels == base_labels + 1 && host.ends_with(&format!(".{base}")) {
                return Some(MatchKind::Wildcard);
            }
        }
    }
    None
}

fn epoch(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map_or(0, |d| d.timestamp())
}

/// Missing dates behave like epoch 0 (crt.sh jq semantics): no `not_after` means not valid.
pub fn currently_valid(
    nb: Option<DateTime<Utc>>,
    na: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let now = now.timestamp();
    epoch(nb) <= now && epoch(na) >= now
}

pub fn future_valid(nb: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    epoch(nb) > now.timestamp()
}

/// Hex serial → lowercase, separators and leading zeros stripped (`0` for empty).
pub fn serial_norm(raw: &str) -> String {
    let hex: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let stripped = hex.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
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

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn observation_source_time_repairs_zoneless_crtsh_timestamps() {
        let rows = vec![CtShRow {
            min_entry_timestamp: Some("2014-04-23 12:16:09".into()),
            ..row(1, "example.com", "2014-04-23 12:16:09")
        }];
        let raw = ct_rows_to_raw_observation(&rows).unwrap();
        assert_eq!(raw.source_time, Some(utc("2014-04-23T12:16:09Z")));
    }

    #[test]
    fn ctdate_appends_zone_when_missing() {
        assert_eq!(ctdate("2014-04-23T12:16:09").unwrap(), utc("2014-04-23T12:16:09Z"));
        assert_eq!(ctdate("2014-04-23 12:16:09").unwrap(), utc("2014-04-23T12:16:09Z"));
        // certwatch DB ::text shape: naive, no zone suffix.
        assert_eq!(ctdate("2026-05-27 00:00:00").unwrap(), utc("2026-05-27T00:00:00Z"));
        assert_eq!(ctdate("2014-04-23T12:16:09Z").unwrap(), utc("2014-04-23T12:16:09Z"));
        assert_eq!(ctdate("2014-04-23T12:16:09+02:00").unwrap(), utc("2014-04-23T10:16:09Z"));
        assert_eq!(ctdate("2014-04-23T12:16:09+0200").unwrap(), utc("2014-04-23T10:16:09Z"));
        assert!(ctdate("").is_none());
        assert!(ctdate("not a date").is_none());
    }

    #[test]
    fn names_splits_lowers_and_dedups() {
        assert_eq!(
            names("WWW.Example.COM\r\nmail.example.com\n\nmail.example.com"),
            vec!["mail.example.com", "www.example.com"]
        );
        assert_eq!(names(""), Vec::<String>::new());
    }

    #[test]
    fn coverage_follows_rfc_6125_single_label() {
        let idents = vec!["example.com".to_string(), "*.example.com".to_string()];
        assert_eq!(coverage(&idents, "example.com"), Some(MatchKind::Exact));
        assert_eq!(coverage(&idents, "www.example.com"), Some(MatchKind::Wildcard));
        assert_eq!(coverage(&idents, "a.b.example.com"), None);
        assert_eq!(coverage(&idents, "other.pl"), None);

        let deep = vec!["*.a.example.com".to_string()];
        assert_eq!(coverage(&deep, "x.a.example.com"), Some(MatchKind::Wildcard));
        assert_eq!(coverage(&deep, "a.example.com"), None);
        assert_eq!(coverage(&deep, "x.y.a.example.com"), None);
    }

    #[test]
    fn serial_norm_strips_separators_and_zeros() {
        assert_eq!(serial_norm("0A:0B:0C"), "a0b0c");
        assert_eq!(serial_norm("00ABC"), "abc");
        assert_eq!(serial_norm("0abc"), "abc");
        assert_eq!(serial_norm("0000"), "0");
        assert_eq!(serial_norm(""), "0");
        assert_eq!(serial_norm("deadbeef"), "deadbeef");
    }

    #[test]
    fn validity_semantics_match_jq_epoch_zero() {
        let now = utc("2026-09-21T12:00:00Z");
        let nb = utc("2026-01-01T00:00:00Z");
        let na = utc("2027-01-01T00:00:00Z");
        assert!(currently_valid(Some(nb), Some(na), now));
        assert!(!future_valid(Some(nb), now));

        let future_nb = utc("2027-06-01T00:00:00Z");
        assert!(!currently_valid(Some(future_nb), Some(na), now));
        assert!(future_valid(Some(future_nb), now));

        assert!(!currently_valid(Some(nb), None, now));
        assert!(!currently_valid(None, None, now));
    }
}
