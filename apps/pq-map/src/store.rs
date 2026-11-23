//! The shared evidence store, as pq-map sees it.
//!
//! Every collection path in pq-map (CT, DNS, TLS probing) goes through the
//! store: collections are keyed, deduplicated, freshness-tracked
//! observations, and this run's scan records exactly which observations it
//! consumed. Transports are the production implementations from `pq-core`
//! (ureq HTTP, std-socket DNS, rustls) — injected so tests can substitute
//! canned ones.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pq_core::evidence::collectors::dns::DnsTransport;
use pq_core::evidence::collectors::dns_transport::UdpTcpDnsTransport;
use pq_core::evidence::collectors::tls_connector::{RustlsConnector, TlsConnector};
use pq_core::evidence::http::{HttpExecutor, UreqExecutor};
use pq_core::evidence::{Store, scan::Scan};

/// Store plus this run's scan and the production transports.
#[derive(Clone)]
pub struct MapEvidence {
    pub store: Arc<Store>,
    pub scan: Scan,
    pub http: Arc<dyn HttpExecutor>,
    pub dns: Arc<dyn DnsTransport>,
    pub tls: Arc<dyn TlsConnector>,
}

impl MapEvidence {
    /// Open (creating if needed) the evidence store under `dir`.
    pub fn open_at(dir: &Path, invocation: serde_json::Value) -> Result<Self, String> {
        let store = Store::open(dir).map_err(|e| format!("evidence store: {e}"))?;
        Ok(Self::new(Arc::new(store), invocation))
    }

    /// Wrap an existing store (tests pass a temp-dir store).
    pub fn new(store: Arc<Store>, invocation: serde_json::Value) -> Self {
        let scan = store
            .begin_scan("pq-map", invocation)
            .expect("scan row created");
        Self {
            store,
            scan,
            http: Arc::new(UreqExecutor::new()),
            dns: Arc::new(UdpTcpDnsTransport::new(std::time::Duration::from_secs(3))),
            tls: Arc::new(RustlsConnector::new(std::time::Duration::from_secs(10))),
        }
    }

    /// Replace a transport (test seam).
    pub fn with_http(mut self, http: Arc<dyn HttpExecutor>) -> Self {
        self.http = http;
        self
    }

    pub fn with_dns(mut self, dns: Arc<dyn DnsTransport>) -> Self {
        self.dns = dns;
        self
    }

    pub fn with_tls(mut self, tls: Arc<dyn TlsConnector>) -> Self {
        self.tls = tls;
        self
    }
}

/// Default store directory: the SHARED pq-intel store
/// (`$XDG_DATA_HOME/pq-intel`, default `~/.local/share/pq-intel`), the
/// same one pq-pulse opens — no tool re-fetches what another already
/// collected. Override with `PQ_MAP_STORE_DIR`.
pub fn default_store_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PQ_MAP_STORE_DIR") {
        return PathBuf::from(dir);
    }
    pq_core::evidence::default_dir().unwrap_or_else(|_| std::env::temp_dir().join("pq-intel"))
}

/// Default invocation payload for the run's scan row.
pub fn invocation_for(args: &[String]) -> serde_json::Value {
    serde_json::json!({ "tool": "pq-map", "argv": args })
}
