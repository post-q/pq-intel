//! Acceptance smoke for pq-map's store cutover: a run completes against a
//! temp store with canned transports (certwatch absent → crt.sh HTTP
//! fallback), and an immediate second run performs ZERO network requests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use pq_core::evidence::collectors::dns::DnsTransport;
use pq_core::evidence::collectors::dns::DnsTransportError;
use pq_core::evidence::collectors::dns::ResolverId;
use pq_core::evidence::collectors::tls_connector::{
    TlsConnectError, TlsConnector, TlsEndpoint, TlsSessionFacts,
};
use pq_core::evidence::http::{HttpExecError, HttpExecutor, HttpRequest, HttpResponse};
use pq_map::store::MapEvidence;

/// Canned HTTP: crt.sh JSON for any request; counts requests.
#[derive(Default)]
struct CountingHttp {
    requests: Mutex<Vec<String>>,
}

impl HttpExecutor for CountingHttp {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpExecError> {
        self.requests.lock().unwrap().push(req.url.clone());
        let body = r#"[
            {"id":1,"issuer_ca_id":42,"issuer_name":"Test CA","name_value":"example.com",
             "common_name":"example.com","not_before":"2026-01-01T00:00:00",
             "not_after":"2027-01-01T00:00:00","serial_number":"0a1b"}
        ]"#;
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            final_url: req.url.clone(),
            redirect_chain: vec![],
        })
    }
}

/// Canned DNS: apex A record; everything else NXDOMAIN.
#[derive(Default)]
struct CountingDns {
    queries: Mutex<usize>,
}

impl DnsTransport for CountingDns {
    fn exchange(
        &self,
        _resolver: &ResolverId,
        message: &Message,
    ) -> Result<Message, DnsTransportError> {
        *self.queries.lock().unwrap() += 1;
        let q = message.queries().first().expect("query");
        let name = q.name().clone();
        let mut response = Message::new();
        response.add_query(Query::query(name.clone(), q.query_type()));
        let qname = name.to_string();
        let qname = qname.trim_end_matches('.');
        if q.query_type() == RecordType::A
            && (qname.starts_with("example.com") || qname == "localhost")
        {
            let ip = if qname == "localhost" {
                hickory_proto::rr::rdata::A::new(127, 0, 0, 1)
            } else {
                A::new(93, 184, 216, 34)
            };
            response.set_response_code(ResponseCode::NoError);
            response.add_answer(Record::from_rdata(name, 300, RData::A(ip)));
        } else {
            response.set_response_code(ResponseCode::NXDomain);
        }
        Ok(response)
    }
}

/// Canned TLS: fixed session facts over the repo test leaf; counts connects.
/// Hosts in `fail_hosts` time out (the connect-class failure that makes a
/// host a sweep target in the collect path).
#[derive(Default)]
struct CountingTls {
    connects: Mutex<usize>,
    fail_hosts: Vec<String>,
}

const TEST_LEAF_PEM: &str = include_str!("data/test-leaf.pem");

fn leaf_der() -> Vec<u8> {
    let body: String = TEST_LEAF_PEM
        .trim()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64_decode(&body)
}

fn base64_decode(s: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match TABLE.iter().position(|t| *t == c) {
            Some(v) => v as u32,
            None => continue,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

impl TlsConnector for CountingTls {
    fn connect(&self, endpoint: &TlsEndpoint) -> Result<TlsSessionFacts, TlsConnectError> {
        *self.connects.lock().unwrap() += 1;
        if self.fail_hosts.iter().any(|h| h == &endpoint.host) {
            return Err(TlsConnectError::Timeout(std::time::Duration::from_millis(
                1,
            )));
        }
        Ok(TlsSessionFacts {
            protocol_version: "TLS 1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            kex_group: "X25519MLKEM768".into(),
            alpn_negotiated: None,
            sni_used: "example.com".into(),
            chain: vec![leaf_der()],
        })
    }
}

fn network_counts(
    http: &CountingHttp,
    dns: &CountingDns,
    tls: &CountingTls,
) -> (usize, usize, usize) {
    (
        http.requests.lock().unwrap().len(),
        *dns.queries.lock().unwrap(),
        *tls.connects.lock().unwrap(),
    )
}

fn canned_evidence(
    store: Arc<pq_core::evidence::Store>,
    http: &Arc<CountingHttp>,
    dns: &Arc<CountingDns>,
    tls: &Arc<CountingTls>,
) -> MapEvidence {
    let ev = MapEvidence::new(store, serde_json::json!({}));
    ev.with_http(http.clone())
        .with_dns(dns.clone())
        .with_tls(tls.clone())
}

/// Serializes the env-setting tests: `std::env::set_var` is process-global
/// and unsynchronized; both tests set the same values but must not race.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[tokio::test]
async fn second_run_performs_zero_network_requests() {
    let _env = env_lock();
    // The certwatch DB is the live CT primary; point it at a closed
    // port with one attempt so its attempts fail fast (recorded as
    // failure observations, then the canned HTTP fallback drives the
    // crawl). This keeps the zero-network assertion about the canned
    // transports, not about crt.sh's connection cap. Both tests in this
    // file set the identical values (env is process-global).
    unsafe {
        std::env::set_var("CT_DB_HOST", "127.0.0.1");
        std::env::set_var("CT_DB_PORT", "1");
        std::env::set_var("CT_RETRIES", "1");
        std::env::set_var("CT_DB_CONNECT_TIMEOUT", "1");
        std::env::set_var("CT_DB_QUERY_TIMEOUT", "1");
    }

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(pq_core::evidence::Store::open(dir.path()).unwrap());
    let http = Arc::new(CountingHttp::default());
    let dns = Arc::new(CountingDns::default());
    let tls = Arc::new(CountingTls::default());

    let ev = canned_evidence(store.clone(), &http, &dns, &tls);
    let cfg = pq_map::config::Config::from_env();
    let state1 = pq_map::collect::collect(
        "example.com",
        &cfg,
        &pq_map::collect::Options {
            refresh: false,
            probe: true,
            ports: None,
        },
        &ev,
    )
    .await
    .expect("first run completes");
    assert!(state1.certs.iter().next().is_some(), "CT data collected");
    let (req1, q1, tls1) = network_counts(&http, &dns, &tls);
    assert!(req1 > 0, "first run collected CT over the network");
    ev.scan.finish().unwrap();

    // Immediate second run over the SAME store: CT within its 30-day
    // policy, DNS within TTL (clamped) and 1h staleness, TLS within its
    // 24h window → zero network requests.
    let ev2 = canned_evidence(store.clone(), &http, &dns, &tls);
    let _state2 = pq_map::collect::collect(
        "example.com",
        &cfg,
        &pq_map::collect::Options {
            refresh: false,
            probe: true,
            ports: None,
        },
        &ev2,
    )
    .await
    .expect("second run completes");
    let (req2, q2, tls2) = network_counts(&http, &dns, &tls);
    assert_eq!(
        (req2, q2, tls2),
        (req1, q1, tls1),
        "second run: zero network requests ({})",
        http.requests.lock().unwrap()[req1..].join(", ")
    );
    ev2.scan.finish().unwrap();

    // Usage classification: first run collected, second cached.
    let scans = store.scans(2).unwrap();
    assert_eq!(scans.len(), 2);
    for (_obs, usage) in store.scan_observations(scans[0].id).unwrap() {
        assert_eq!(
            usage,
            pq_core::evidence::Usage::Cached,
            "second run served everything from the store"
        );
    }
    let usages: Vec<pq_core::evidence::Usage> = store
        .scan_observations(scans[1].id)
        .unwrap()
        .into_iter()
        .map(|(_, u)| u)
        .collect();
    assert!(
        usages.contains(&pq_core::evidence::Usage::Collected),
        "first run collected"
    );
}

#[tokio::test]
async fn ports_sweep_runs_the_shared_collector() {
    let _env = env_lock();
    // Identical env values as the test above (env is process-global).
    unsafe {
        std::env::set_var("CT_DB_HOST", "127.0.0.1");
        std::env::set_var("CT_DB_PORT", "1");
        std::env::set_var("CT_RETRIES", "1");
        std::env::set_var("CT_DB_CONNECT_TIMEOUT", "1");
        std::env::set_var("CT_DB_QUERY_TIMEOUT", "1");
    }

    // A real listener on loopback: the shared ports collector connects for
    // real (the sweep has no transport seam), so the swept port is one we
    // own. `localhost` resolves offline through the system resolver.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(pq_core::evidence::Store::open(dir.path()).unwrap());
    let tls = Arc::new(CountingTls {
        fail_hosts: vec!["localhost".into()],
        ..Default::default()
    });

    // The apex (`localhost`) times out on the canned TLS probe — the
    // connect-class failure that makes a host a sweep target.
    let ev = canned_evidence(
        store.clone(),
        &Arc::new(CountingHttp::default()),
        &Arc::new(CountingDns::default()),
        &tls,
    );
    let cfg = pq_map::config::Config::from_env();
    let opts = pq_map::collect::Options {
        refresh: false,
        probe: true,
        ports: Some(vec![open_port]),
    };
    let state1 = pq_map::collect::collect("localhost", &cfg, &opts, &ev)
        .await
        .expect("first run completes");

    let swept = state1
        .hosts
        .get("localhost")
        .expect("apex host present")
        .ports
        .iter()
        .find(|s| s.port == open_port)
        .expect("explicit port swept");
    assert_eq!(
        swept.state,
        pq_map::model::ScanState::Open,
        "bound port sweeps open"
    );

    use pq_core::evidence::CollectionRequest;
    let ports_key =
        pq_core::evidence::collectors::ports::PortsRequest::new("localhost", &[open_port])
            .unwrap()
            .key();
    let obs1 = store
        .latest_usable_observation(&ports_key)
        .unwrap()
        .expect("sweep recorded as a usable success observation");
    ev.scan.finish().unwrap();

    // Immediate second run over the SAME store: the sweep is within its
    // TTL, so the store serves it (Cached) and no connect happens. The
    // apex's failed TLS probe IS re-attempted — a failure is never a
    // usable answer, and the file cache that used to suppress the retry
    // is gone.
    let ev2 = canned_evidence(
        store.clone(),
        &Arc::new(CountingHttp::default()),
        &Arc::new(CountingDns::default()),
        &tls,
    );
    let state2 = pq_map::collect::collect("localhost", &cfg, &opts, &ev2)
        .await
        .expect("second run completes");
    let reswept = state2
        .hosts
        .get("localhost")
        .unwrap()
        .ports
        .iter()
        .find(|s| s.port == open_port)
        .expect("second run still reports the swept port");
    assert_eq!(reswept.state, pq_map::model::ScanState::Open);
    ev2.scan.finish().unwrap();

    let mut saw_collected = false;
    let mut saw_cached = false;
    for s in store.scans(10).unwrap() {
        for (id, usage) in store.scan_observations(s.id).unwrap() {
            if id == obs1.id {
                match usage {
                    pq_core::evidence::Usage::Collected => saw_collected = true,
                    pq_core::evidence::Usage::Cached => saw_cached = true,
                    _ => {}
                }
            }
        }
    }
    assert!(saw_collected, "first run swept fresh (Collected)");
    assert!(
        saw_cached,
        "second run served the sweep from the store (Cached)"
    );
}

#[allow(dead_code)]
fn type_witnesses(map: BTreeMap<u16, u16>) {
    let _ = map;
}
