//! Observation types: what a collection produced and how it is stored.

use crate::evidence::key::CollectionKey;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::borrow::Cow;

/// Normalized observation status. The closed set from the spec; the
/// protocol-level status is preserved separately in `native_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationStatus {
    Success,
    NotFound,
    Timeout,
    RateLimited,
    Error,
}

impl ObservationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ObservationStatus::Success => "success",
            ObservationStatus::NotFound => "not_found",
            ObservationStatus::Timeout => "timeout",
            ObservationStatus::RateLimited => "rate_limited",
            ObservationStatus::Error => "error",
        }
    }

    #[allow(clippy::should_implement_trait)] // inherent-by-choice; not a FromStr impl
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "success" => ObservationStatus::Success,
            "not_found" => ObservationStatus::NotFound,
            "timeout" => ObservationStatus::Timeout,
            "rate_limited" => ObservationStatus::RateLimited,
            "error" => ObservationStatus::Error,
            _ => return None,
        })
    }

    /// A usable answer: either a positive result or a valid negative one
    /// (NXDOMAIN is knowledge; a timeout is not). Failed collections never
    /// overwrite the last usable result.
    pub const fn is_usable(self) -> bool {
        matches!(
            self,
            ObservationStatus::Success | ObservationStatus::NotFound
        )
    }
}

/// An observation produced by a collector, not yet persisted.
pub struct RawObservation {
    pub status: ObservationStatus,
    /// Protocol-level status, preserved verbatim: HTTP status code, DNS rcode
    /// name, RDAP HTTP status, TLS alert description, ...
    pub native_status: Option<String>,
    /// When the source claims the data was measured (e.g. RIPEstat
    /// `currenttime`, a certificate's notBefore). Distinct from `observed_at`.
    pub source_time: Option<DateTime<Utc>>,
    /// Small structured result. Bulk evidence goes to artifacts.
    pub metadata: Value,
    /// Bulk evidence produced with this observation.
    pub artifacts: Vec<RawArtifact>,
    /// Source-provided freshness hint (DNS TTL, SOA negative TTL). Combined
    /// with the policy to compute `fresh_until`.
    pub fresh_hint: Option<std::time::Duration>,
    /// Policy name this outcome should be evaluated under (e.g. DNS
    /// collectors route negative answers to the `negative` policy). `None` =
    /// the request's default policy.
    pub policy_name: Option<Cow<'static, str>>,
    /// When this observation confirms (rather than replaces) a prior stored
    /// representation — HTTP 304. The driver re-links the prior observation's
    /// artifacts for roles this outcome does not itself provide, so no
    /// duplicate body artifact is created.
    pub confirms: Option<i64>,
}

impl RawObservation {
    pub fn success(metadata: Value) -> Self {
        Self {
            status: ObservationStatus::Success,
            native_status: None,
            source_time: None,
            metadata,
            artifacts: Vec::new(),
            fresh_hint: None,
            policy_name: None,
            confirms: None,
        }
    }
}

/// Unpersisted bulk evidence.
pub struct RawArtifact {
    pub role: Cow<'static, str>,
    pub bytes: Vec<u8>,
    pub content_type: Cow<'static, str>,
}

/// Artifact compression, stored as metadata next to the content hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    Zstd,
    None,
}

impl Compression {
    pub const fn as_str(self) -> &'static str {
        match self {
            Compression::Zstd => "zstd",
            Compression::None => "none",
        }
    }

    #[allow(clippy::should_implement_trait)] // inherent-by-choice; not a FromStr impl
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "zstd" => Compression::Zstd,
            "none" => Compression::None,
            _ => return None,
        })
    }
}

/// Catalog entry for a stored artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactMeta {
    pub hash: [u8; 32],
    pub size_uncompressed: u64,
    pub compression: Compression,
    pub content_type: String,
}

impl ArtifactMeta {
    pub fn hex(&self) -> String {
        crate::evidence::key::hex(&self.hash)
    }
}

/// An artifact linked to a stored observation under a role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactLink {
    pub role: String,
    pub artifact: ArtifactMeta,
}

/// A persisted observation.
#[derive(Clone, Debug)]
pub struct StoredObservation {
    pub id: i64,
    pub key: CollectionKey,
    pub kind: String,
    pub status: ObservationStatus,
    pub native_status: Option<String>,
    pub observed_at: i64,
    pub source_time: Option<i64>,
    pub fresh_until: Option<i64>,
    pub metadata: Value,
    pub artifacts: Vec<ArtifactLink>,
    pub scan_id: i64,
}

impl StoredObservation {
    /// UTC time of collection.
    pub fn observed_at_time(&self) -> Option<DateTime<Utc>> {
        chrono::DateTime::from_timestamp(self.observed_at, 0)
    }

    pub fn source_at_time(&self) -> Option<DateTime<Utc>> {
        chrono::DateTime::from_timestamp(self.source_time?, 0)
    }

    pub fn artifact_by_role(&self, role: &str) -> Option<&ArtifactMeta> {
        self.artifacts
            .iter()
            .find(|l| l.role == role)
            .map(|l| &l.artifact)
    }
}
