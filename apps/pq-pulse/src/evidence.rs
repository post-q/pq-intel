//! The evidence-store integration: one shared store, one scan per tool run,
//! and the collector stack (production or canned for tests).

use std::sync::Arc;

use pq_core::evidence::Scan;
use pq_core::evidence::collectors::dns::{DnsCollector, DnsTransport, ResolverId};
use pq_core::evidence::collectors::dns_transport::CompositeDnsTransport;
use pq_core::evidence::collectors::http_collector::HttpCollector;
use pq_core::evidence::collectors::rdap::RdapCollector;
use pq_core::evidence::collectors::tls::TlsCollector;
use pq_core::evidence::collectors::tls_connector::{RustlsConnector, TlsConnector};
use pq_core::evidence::http::{HttpExecutor, UreqExecutor};
use pq_core::evidence::store::Store;
use serde_json::json;

/// Query timeout for the shared transports.
const TRANSPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The store-backed context for one pq-pulse run: the shared store, this
/// run's scan (which records exactly which observations the run consumed),
/// and the collectors over their transport seams.
#[derive(Clone)]
pub struct Evidence {
    pub store: Arc<Store>,
    pub scan: Scan,
    pub dns: DnsCollector,
    pub http: HttpCollector,
    pub rdap: RdapCollector,
    pub tls: TlsCollector,
    /// The shared HTTP executor, for collectors built ad hoc (RDAP helper
    /// instances, vendor-range fetches).
    pub http_executor: Arc<dyn HttpExecutor>,
}

impl Evidence {
    /// Production stack over the default store location (or an explicit
    /// directory).
    pub fn open(
        store_dir: Option<&std::path::Path>,
        invocation: serde_json::Value,
    ) -> Result<Self, pq_core::evidence::Error> {
        let store = match store_dir {
            Some(dir) => Store::open(dir)?,
            None => Store::open_default()?,
        };
        Ok(Self::new(Arc::new(store), invocation))
    }

    /// Production collectors over an existing store.
    pub fn new(store: Arc<Store>, invocation: serde_json::Value) -> Self {
        let http: Arc<dyn HttpExecutor> = Arc::new(UreqExecutor::new());
        let dns: Arc<dyn DnsTransport> = Arc::new(CompositeDnsTransport::production(
            http.clone(),
            TRANSPORT_TIMEOUT,
        ));
        Self::with_transports(
            store,
            invocation,
            http,
            dns,
            Arc::new(RustlsConnector::new(TRANSPORT_TIMEOUT)),
        )
    }

    /// Explicit transport stack — the seam the offline acceptance tests use.
    pub fn with_transports(
        store: Arc<Store>,
        invocation: serde_json::Value,
        http: Arc<dyn HttpExecutor>,
        dns: Arc<dyn DnsTransport>,
        tls: Arc<dyn TlsConnector>,
    ) -> Self {
        let scan = store
            .begin_scan("pq-pulse", invocation)
            .expect("scan row created");
        Self {
            store,
            scan,
            dns: DnsCollector::new(dns),
            http: HttpCollector { http: http.clone() },
            rdap: RdapCollector { http: http.clone() },
            tls: TlsCollector { connector: tls },
            http_executor: http,
        }
    }

    /// Resolver identity for the DoH fallback (a DNS-kind observation over
    /// HTTP transport, distinct source identity).
    pub fn doh_resolver() -> ResolverId {
        ResolverId::DoH("https://cloudflare-dns.com/dns-query".into())
    }

    /// Finish the run's scan (records `finished_at`).
    pub fn finish(self) -> Result<(), pq_core::evidence::Error> {
        self.scan.finish()
    }
}

/// Default invocation payload for the run's scan row.
pub fn invocation_for(args: &[String]) -> serde_json::Value {
    json!({ "tool": "pq-pulse", "argv": args })
}

/// Offline test support: transports that fail fast (no network), over a
/// throwaway store. Tests that only exercise non-collection paths build
/// their `Evidence` here.
pub mod testing {
    use super::*;
    use pq_core::evidence::collectors::tls_connector::{TlsConnectError, TlsEndpoint};
    use pq_core::evidence::http::{HttpExecError, HttpRequest, HttpResponse};

    pub struct FailingHttpExecutor;
    impl HttpExecutor for FailingHttpExecutor {
        fn execute(&self, _req: &HttpRequest) -> Result<HttpResponse, HttpExecError> {
            Err(HttpExecError::Connection("offline test: no network".into()))
        }
    }

    pub struct FailingDnsTransport;
    impl DnsTransport for FailingDnsTransport {
        fn exchange(
            &self,
            _resolver: &ResolverId,
            _message: &hickory_proto::op::Message,
        ) -> Result<hickory_proto::op::Message, pq_core::evidence::collectors::dns::DnsTransportError>
        {
            Err(
                pq_core::evidence::collectors::dns::DnsTransportError::Network(
                    "offline test: no network".into(),
                ),
            )
        }
    }

    pub struct FailingTlsConnector;
    impl pq_core::evidence::collectors::tls_connector::TlsConnector for FailingTlsConnector {
        fn connect(
            &self,
            _endpoint: &TlsEndpoint,
        ) -> Result<pq_core::evidence::collectors::tls_connector::TlsSessionFacts, TlsConnectError>
        {
            Err(TlsConnectError::Connection(
                "offline test: no network".into(),
            ))
        }
    }

    /// Offline evidence context over a throwaway store. Caller keeps the
    /// `TempDir` alive as long as the `Evidence`.
    pub fn offline_evidence(invocation: serde_json::Value) -> (tempfile::TempDir, Evidence) {
        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Store::open(dir.path()).expect("temp store");
        let evidence = Evidence::with_transports(
            std::sync::Arc::new(store),
            invocation,
            std::sync::Arc::new(FailingHttpExecutor),
            std::sync::Arc::new(FailingDnsTransport),
            std::sync::Arc::new(FailingTlsConnector),
        );
        (dir, evidence)
    }
}
