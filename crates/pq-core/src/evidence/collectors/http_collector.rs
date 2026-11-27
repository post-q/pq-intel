//! The HTTP collector: URL-targeted collection with status, headers, body,
//! redirect chain, and conditional revalidation.
//!
//! Revalidation: when the stored observation carries validators (`ETag`,
//! `Last-Modified`), a stale revalidation sends `If-None-Match` /
//! `If-Modified-Since`. A 304 confirms the cached representation — the new
//! observation links the SAME body artifact (dedup by content hash) with
//! fresh response headers, costing one 304 response instead of a full
//! re-download.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::Result;
use crate::evidence::http::{HttpExecError, HttpExecutor, HttpMethod, HttpRequest};
use crate::evidence::key::{CanonicalWriter, CollectionRequest, canonical_url};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest_ {
    pub url: String,
    pub method: HttpMethod,
    /// Request headers that affect the response and belong in the identity
    /// (e.g. `Accept`). Credentials/secrets are NEVER put here — they go in
    /// [`HttpRequest_::secrets`], which is used only at collection time and
    /// structurally excluded from keys and stored parameters.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub secrets: Vec<(String, String)>,
    pub timeout: Duration,
}

impl HttpRequest_ {
    pub fn get(url: &str) -> Result<Self> {
        Ok(Self {
            url: canonical_url(url)?,
            method: HttpMethod::Get,
            headers: vec![],
            body: None,
            secrets: vec![],
            timeout: Duration::from_secs(10),
        })
    }
}

/// Decoded HTTP observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpObservation {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub final_url: String,
    pub redirect_chain: Vec<String>,
}

/// The HTTP collector. Clones share the executor.
#[derive(Clone)]
pub struct HttpCollector {
    pub http: Arc<dyn HttpExecutor>,
}

/// Pure mapping: HTTP status → (observation status, native status). Exposed
/// for unit tests and shared by every HTTP-speaking collector.
///
/// Semantics: 2xx/3xx are successes; 404/410 are valid negative answers;
/// 429 is rate limiting; 5xx is a server error. Any other 4xx (401, 403,
/// 405, ...) is a complete, meaningful response — positive evidence of an
/// access-control surface — recorded as success with the native code
/// preserved.
pub fn response_to_observation_parts(
    status: u16,
) -> (
    crate::evidence::observation::ObservationStatus,
    Option<String>,
) {
    let native = Some(status.to_string());
    match status {
        200..=399 => (
            crate::evidence::observation::ObservationStatus::Success,
            native,
        ),
        404 | 410 => (
            crate::evidence::observation::ObservationStatus::NotFound,
            native,
        ),
        429 => (
            crate::evidence::observation::ObservationStatus::RateLimited,
            native,
        ),
        500..=599 => (
            crate::evidence::observation::ObservationStatus::Error,
            native,
        ),
        _ => (
            crate::evidence::observation::ObservationStatus::Success,
            native,
        ),
    }
}

impl Collector for HttpCollector {
    type Request = HttpRequest_;
    type Output = HttpObservation;

    fn collect(
        &self,
        _scan: &Scan,
        req: &HttpRequest_,
        prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        // Conditional revalidation: validators from the prior observation's
        // metadata.
        let mut headers = req.headers.clone();
        if let Some(prior) = prior {
            if let Some(etag) = prior.metadata.get("etag").and_then(|v| v.as_str()) {
                headers.push(("if-none-match".to_string(), etag.to_string()));
            }
            if let Some(lm) = prior.metadata.get("last_modified").and_then(|v| v.as_str()) {
                headers.push(("if-modified-since".to_string(), lm.to_string()));
            }
        }
        let conditional = headers.len() != req.headers.len();

        let request = HttpRequest {
            url: req.url.clone(),
            method: req.method,
            headers: req.secrets.iter().chain(headers.iter()).cloned().collect(),
            body: req.body.clone(),
            timeout: req.timeout,
        };
        let response = match self.http.execute(&request) {
            Ok(response) => response,
            Err(HttpExecError::Timeout(d)) => {
                return Err(CollectionError::Timeout {
                    native: Some(format!("timed out after {d:?}")),
                });
            }
            Err(HttpExecError::RateLimited(status)) => {
                return Err(CollectionError::RateLimited {
                    native: Some(status.to_string()),
                });
            }
            // The endpoint answered: nothing listens. Definitive endpoint
            // absence - an answer, recorded as knowledge, like a dns
            // NXDOMAIN.
            Err(HttpExecError::Refused) => {
                return Ok(super::closed_observation("http:closed", &req.url));
            }
            Err(other) => {
                return Err(CollectionError::Error {
                    native: None,
                    message: other.to_string(),
                });
            }
        };

        let (status, native) = response_to_observation_parts(response.status);

        if response.status == 304 {
            // Confirmed: same representation. The driver re-links the prior
            // observation's body/redirect artifacts; headers come fresh.
            let prior_id = prior.expect("304 requires a prior observation").id;
            let mut raw = RawObservation::success(serde_json::json!({
                "final_url": response.final_url,
                "status": 304,
                "etag": header_of(&response.headers, "etag"),
                "last_modified": header_of(&response.headers, "last-modified"),
                "revalidated": true,
            }));
            raw.native_status = native;
            raw.confirms = Some(prior_id);
            raw.artifacts.push(headers_artifact(&response.headers));
            return Ok(raw);
        }

        let mut raw = RawObservation::success(serde_json::json!({
            "final_url": response.final_url,
            "status": response.status,
            "etag": header_of(&response.headers, "etag"),
            "last_modified": header_of(&response.headers, "last-modified"),
        }));
        raw.status = status;
        raw.native_status = native;
        raw.artifacts.push(headers_artifact(&response.headers));
        if !response.body.is_empty() {
            raw.artifacts.push(RawArtifact {
                role: "response_body".into(),
                bytes: response.body.clone(),
                content_type: header_of(&response.headers, "content-type")
                    .unwrap_or("application/octet-stream")
                    .to_string()
                    .into(),
            });
        }
        if !response.redirect_chain.is_empty() {
            raw.artifacts.push(RawArtifact {
                role: "redirect_chain".into(),
                bytes: serde_json::to_vec(&response.redirect_chain).map_err(|e| {
                    CollectionError::Error {
                        native: None,
                        message: format!("redirect chain: {e}"),
                    }
                })?,
                content_type: "application/json; role=redirect-chain".into(),
            });
        }
        let _ = conditional;
        Ok(raw)
    }

    fn decode(&self, store: &Store, obs: &StoredObservation) -> Result<HttpObservation> {
        // A refusal carries no response at all: empty typed view, and the
        // missing response_headers artifact is the answer's shape, not
        // corruption.
        let refusal = super::is_closed_observation(obs);
        let headers_artifact = obs.artifact_by_role("response_headers");
        let headers: Vec<(String, String)> = match headers_artifact {
            Some(a) => serde_json::from_slice(&store.read_artifact(a)?)?,
            None if refusal => vec![],
            None => {
                return Err(crate::evidence::error::Error::Misuse(format!(
                    "observation {} has no response_headers artifact",
                    obs.id
                )));
            }
        };
        let body = match obs.artifact_by_role("response_body") {
            Some(meta) => store.read_artifact(meta)?,
            None => vec![],
        };
        let redirect_chain = match obs.artifact_by_role("redirect_chain") {
            Some(meta) => serde_json::from_slice(&store.read_artifact(meta)?)?,
            None => vec![],
        };
        Ok(HttpObservation {
            status: obs
                .metadata
                .get("status")
                .and_then(|v| v.as_u64())
                .unwrap_or_default() as u16,
            headers,
            body,
            final_url: obs
                .metadata
                .get("final_url")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            redirect_chain,
        })
    }
}

fn headers_artifact(headers: &[(String, String)]) -> RawArtifact {
    RawArtifact {
        role: "response_headers".into(),
        bytes: serde_json::to_vec(headers).expect("header json serialization"),
        content_type: "application/json; role=response-headers".into(),
    }
}

fn header_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

impl CollectionRequest for HttpRequest_ {
    const KIND: &'static str = "http";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("method", self.method.as_str());
        w.str_field("url", &self.url);
        w.pair_list_field("headers", &self.headers);
        match &self.body {
            Some(b) => w.bytes_field("body_sha256", &{
                use sha2::{Digest, Sha256};
                let d: [u8; 32] = Sha256::digest(b).into();
                d
            }),
            None => w.opt_bytes_field("body_sha256", None),
        }
        // secrets deliberately never written
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({
            "method": self.method.as_str(),
            "url": self.url,
            "headers": self.headers,
            "body_sha256": self.body.as_ref().map(|b| crate::evidence::key::hex(&{
                use sha2::{Digest, Sha256};
                Sha256::digest(b)
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_semantics_map_to_the_closed_set() {
        let (s, n) = response_to_observation_parts(200);
        assert_eq!(s, crate::evidence::observation::ObservationStatus::Success);
        assert_eq!(n.as_deref(), Some("200"));
        let (s, _) = response_to_observation_parts(403);
        assert_eq!(
            s,
            crate::evidence::observation::ObservationStatus::Success,
            "access-control responses are positive evidence"
        );
        let (s, _) = response_to_observation_parts(404);
        assert_eq!(s, crate::evidence::observation::ObservationStatus::NotFound);
        let (s, _) = response_to_observation_parts(429);
        assert_eq!(
            s,
            crate::evidence::observation::ObservationStatus::RateLimited
        );
        let (s, _) = response_to_observation_parts(502);
        assert_eq!(s, crate::evidence::observation::ObservationStatus::Error);
    }

    #[test]
    fn equivalent_urls_share_identity() {
        let a = HttpRequest_::get("https://example.com:443/x").unwrap();
        let b = HttpRequest_::get("HTTPS://EXAMPLE.COM/x").unwrap();
        assert_eq!(a.key(), b.key());
    }
}
