//! The shared HTTP executor seam.
//!
//! Every HTTP-speaking collector (HTTP, DoH, RDAP, RIPEstat, CT-HTTP
//! fallback) runs its requests through this trait; tests install a canned
//! executor, production uses [`UreqExecutor`]. No collector constructs its
//! own client.

use crate::evidence::error::Result;
use std::io::Read;
use std::time::Duration;

/// A wire-level HTTP request (no collector-specific semantics).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

/// A wire-level HTTP response. Redirects are followed by the executor; the
/// chain (original URL → final URL) is reported so redirect provenance is
/// preserved.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// URL the response actually came from (after redirects).
    pub final_url: String,
    /// Each hop of the redirect chain (Location targets), in order; empty
    /// when there were none.
    pub redirect_chain: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpExecError {
    /// Transport gave up: connection refused/reset, TLS failure.
    #[error("connection failed: {0}")]
    Connection(String),
    /// The response did not arrive within the timeout — recorded as
    /// "unknown", never as "nonexistent".
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    /// Server signaled rate limiting.
    #[error("rate limited (status {0})")]
    RateLimited(u16),
    #[error("malformed response: {0}")]
    Malformed(String),
}

impl From<HttpExecError> for crate::evidence::collector::CollectionError {
    fn from(e: HttpExecError) -> Self {
        match e {
            HttpExecError::Timeout(_) => crate::evidence::collector::CollectionError::Timeout {
                native: Some(e.to_string()),
            },
            HttpExecError::RateLimited(status) => {
                crate::evidence::collector::CollectionError::RateLimited {
                    native: Some(status.to_string()),
                }
            }
            other => crate::evidence::collector::CollectionError::Error {
                native: None,
                message: other.to_string(),
            },
        }
    }
}

/// Blocking HTTP executor seam.
pub trait HttpExecutor: Send + Sync {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpExecError>;
}

/// Production executor over `ureq` (rustls), redirect-following with chain
/// capture.
pub struct UreqExecutor {
    agent: ureq::Agent,
}

impl UreqExecutor {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new().redirects(10).build(),
        }
    }
}

impl Default for UreqExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpExecutor for UreqExecutor {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpExecError> {
        // Redirects are followed manually (bounded) so the chain is recorded
        // per hop — redirect provenance is part of the evidence.
        let mut url = req.url.clone();
        let mut redirect_chain = Vec::new();
        for _hop in 0..MAX_REDIRECTS {
            let mut request = self
                .agent
                .request(req.method.as_str(), &url)
                .timeout(req.timeout);
            for (name, value) in &req.headers {
                request = request.set(name, value);
            }
            let response = match (&req.method, &req.body) {
                (HttpMethod::Get, _) => request.call(),
                (HttpMethod::Post, Some(body)) => request.send_bytes(body),
                (HttpMethod::Post, None) => request.call(),
            };
            let response = match response {
                Ok(r) => r,
                Err(ureq::Error::Status(_code, r)) => r,
                Err(ureq::Error::Transport(t)) => {
                    if t.kind() == ureq::ErrorKind::Io
                        && t.message()
                            .is_some_and(|m| m.contains("timed out") || m.contains("timeout"))
                    {
                        return Err(HttpExecError::Timeout(req.timeout));
                    }
                    return Err(HttpExecError::Connection(t.to_string()));
                }
            };
            let status = response.status();
            let is_redirect =
                matches!(status, 301 | 302 | 303 | 307 | 308) && req.method == HttpMethod::Get;
            if is_redirect {
                if let Some(location) = response.header("location") {
                    let next = resolve_location(&url, location)?;
                    redirect_chain.push(next.clone());
                    url = next;
                    continue;
                }
            }
            let headers: Vec<(String, String)> = response
                .headers_names()
                .into_iter()
                .filter_map(|name| {
                    response
                        .header(&name)
                        .map(|v| (name.to_ascii_lowercase(), v.to_string()))
                })
                .collect();
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_BODY_BYTES)
                .read_to_end(&mut body)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.to_string().contains("timed out")
                    {
                        HttpExecError::Timeout(req.timeout)
                    } else {
                        HttpExecError::Malformed(e.to_string())
                    }
                })?;
            return Ok(HttpResponse {
                status,
                headers,
                body,
                final_url: url,
                redirect_chain,
            });
        }
        Err(HttpExecError::Malformed(format!(
            "more than {MAX_REDIRECTS} redirects from {}",
            req.url
        )))
    }
}

const MAX_REDIRECTS: usize = 10;
/// 256 MiB cap, as the existing crt.sh fetch path uses.
const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;

fn resolve_location(base: &str, location: &str) -> Result<String, HttpExecError> {
    url::Url::parse(location)
        .or_else(|_| url::Url::parse(base).and_then(|b| b.join(location)))
        .map(|u| u.to_string())
        .map_err(|e| {
            HttpExecError::Malformed(format!("unresolvable redirect location `{location}`: {e}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_locations() {
        assert_eq!(
            resolve_location("https://a.example/x/y", "/z").unwrap(),
            "https://a.example/z"
        );
        assert_eq!(
            resolve_location("https://a.example/x/y", "https://b.example/").unwrap(),
            "https://b.example/"
        );
    }
}
