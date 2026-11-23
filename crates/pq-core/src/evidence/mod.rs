//! The shared evidence and knowledge store.
//!
//! One SQLite database plus content-addressed artifact files, shared by all
//! pq-intel tools on one machine. Design invariants (each exercised through
//! this public API in the integration tests):
//!
//! - **Append-only observations.** A failed collection (timeout, rate limit,
//!   error) is recorded and never overwrites the last usable result; a
//!   timeout is "unknown", never "nonexistent".
//! - **Freshness labels never lie.** [`freshness::DataStatus`] is computed
//!   from policy math ([`policy::Policy::fresh_until`], TTL clamping) and is
//!   never a claim of verified currency.
//! - **On-read, blocking revalidation.** [`scan::Scan::collect`] serves from
//!   the store when the [`freshness::FreshnessRequirement`] and the policy
//!   permit; otherwise it collects synchronously.
//! - **Single-flight.** Concurrent identical requests share one in-flight
//!   collection.
//! - **Artifacts** are SHA-256-content-addressed (of the original
//!   uncompressed bytes), Zstandard-compressed, deduplicated globally, and
//!   written crash-safely (temp → verify → publish → catalog).
//! - **Canonical identity.** Collection keys are versioned SHA-256 hashes of
//!   a canonical request form; equivalent requests deduplicate, differing
//!   parameters never collide, secrets never enter keys or stored params.
//! - **Scans** record exactly which observations each run consumed, with a
//!   usage class per observation.
//!
//! Collectors ([`collector::Collector`]) define each collection kind (DNS,
//! DoH, HTTP, TLS, CT, RDAP, RIPEstat) behind transport seams
//! ([`http::HttpExecutor`], the DNS transport, the TLS connector), so all
//! tests run offline against canned transports.

pub mod artifact;
pub mod collector;
pub mod error;
pub mod flight;
pub mod freshness;
pub mod key;
pub mod observation;
pub mod policy;
pub mod scan;
pub mod schema;
pub mod store;

pub mod collectors;
pub mod http;

pub use error::{Error, Result};
pub use freshness::{DataStatus, FreshnessRequirement};
pub use key::{CollectionKey, CollectionRequest};
pub use observation::{Compression, ObservationStatus, StoredObservation};
pub use policy::Policy;
pub use scan::{Collected, RecordedFailure, Scan};
pub use store::{Store, StoreOptions, Usage, now_secs};

/// Open the store at the platform default location
/// (`$XDG_DATA_HOME/pq-intel/evidence.db`, else `~/.local/share`).
pub fn open_default() -> Result<Store> {
    Store::open_default()
}

/// Open the store under a specific data directory (creates it if needed).
pub fn open(data_dir: &std::path::Path) -> Result<Store> {
    Store::open(data_dir)
}

/// Default store location helper (exposed for CLIs' `--store` overrides).
pub fn default_dir() -> Result<std::path::PathBuf> {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(xdg) if !xdg.is_empty() => Ok(std::path::PathBuf::from(xdg).join("pq-intel")),
        _ => {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| Error::Misuse("neither XDG_DATA_HOME nor HOME is set".into()))?;
            Ok(std::path::PathBuf::from(home).join(".local/share/pq-intel"))
        }
    }
}

/// Convenience: variant re-exports used in match arms.
pub use freshness::FreshnessRequirement::{Cached, Historical, MaxAge, Refresh};
