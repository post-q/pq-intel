//! Acceptance smoke (the v1 acceptance): a run completes against a temp
//! store with canned transports, and an immediate second run performs ZERO
//! network requests.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use pq_core::evidence::collectors::dns::DnsTransport;
use pq_core::evidence::collectors::dns::DnsTransportError;
use pq_core::evidence::collectors::dns::ResolverId;
use pq_core::evidence::collectors::tls_connector::{
    TlsConnectError, TlsConnector, TlsEndpoint, TlsSessionFacts,
};
use pq_core::evidence::http::{HttpExecError, HttpExecutor, HttpRequest, HttpResponse};
use pq_core::evidence::key::CollectionRequest;
use pq_pulse::detect::{ScanContext, check_domain};
use pq_pulse::evidence::Evidence;

/// Canned HTTP: fixed response for any request; counts requests.
#[derive(Default)]
struct CountingHttp {
    requests: Mutex<Vec<String>>,
}

impl HttpExecutor for CountingHttp {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpExecError> {
        self.requests.lock().unwrap().push(req.url.clone());
        Ok(HttpResponse {
            status: 200,
            headers: vec![
                ("server".into(), "cloudflare".into()),
                ("content-type".into(), "text/html".into()),
            ],
            body: b"<html><title>Firm</title></html>".to_vec(),
            final_url: "https://example.com/".into(),
            redirect_chain: vec![],
        })
    }
}

/// Canned DNS: A + PTR answers; counts queries.
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
        response.set_response_code(ResponseCode::NoError);
        response.add_query(Query::query(name.clone(), q.query_type()));
        match q.query_type() {
            RecordType::A => {
                response.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::A(A::new(93, 184, 216, 34)),
                ));
            }
            RecordType::PTR => {
                response.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::PTR(hickory_proto::rr::rdata::name::PTR(
                        Name::from_utf8("host.example.com.").unwrap(),
                    )),
                ));
            }
            // Everything else (AAAA, CNAME, MX, TXT, …): valid negative.
            _ => {
                response.set_response_code(ResponseCode::NXDomain);
            }
        }
        Ok(response)
    }
}

/// Canned TLS: fixed session facts; counts connects.
#[derive(Default)]
struct CountingTls {
    connects: Mutex<usize>,
}

impl TlsConnector for CountingTls {
    fn connect(&self, _endpoint: &TlsEndpoint) -> Result<TlsSessionFacts, TlsConnectError> {
        *self.connects.lock().unwrap() += 1;
        Ok(TlsSessionFacts {
            protocol_version: "TLS 1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            kex_group: "X25519MLKEM768".into(),
            alpn_negotiated: None,
            sni_used: "example.com".into(),
            chain: vec![b"leaf-der".to_vec()],
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

#[test]
fn second_run_performs_zero_network_requests() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(pq_core::evidence::Store::open(dir.path()).unwrap());
    let http = Arc::new(CountingHttp::default());
    let dns = Arc::new(CountingDns::default());
    let tls = Arc::new(CountingTls::default());

    let evidence = Evidence::with_transports(
        store.clone(),
        serde_json::json!({"run": 1}),
        http.clone(),
        dns.clone(),
        tls.clone(),
    );
    let context = ScanContext::unlimited(evidence);
    let report1 = check_domain("example.com", &context).expect("first run completes");
    assert!(
        matches!(report1.tls, pq_pulse::model::TlsState::Tls(_)),
        "TLS observation recorded"
    );
    let (req1, q1, tls1) = network_counts(&http, &dns, &tls);
    assert!(
        req1 > 0 && q1 > 0 && tls1 > 0,
        "first run collected over the network"
    );
    context.store_evidence.scan.finish().unwrap();

    // Immediate second run over the SAME store: every collection is within
    // its freshness window (DNS TTL 300s, HTTP/TLS 24h, RDAP 7d, CT/RDAP
    // bootstrap indefinite) → zero network requests.
    let evidence2 = Evidence::with_transports(
        store.clone(),
        serde_json::json!({"run": 2}),
        http.clone(),
        dns.clone(),
        tls.clone(),
    );
    let context2 = ScanContext::unlimited(evidence2);
    let _report2 = check_domain("example.com", &context2).expect("second run completes");
    let (req2, q2, tls2) = network_counts(&http, &dns, &tls);
    assert_eq!(
        (req2, q2, tls2),
        (req1, q1, tls1),
        "second run: zero network requests ({})",
        http.requests.lock().unwrap()[req1..].join(", ")
    );
    context2.store_evidence.scan.finish().unwrap();

    // Usage classification: run 1 collected, run 2 cached.
    let scans = store.scans(2).unwrap();
    assert_eq!(scans.len(), 2);
    let (_obs, usage1) = &store.scan_observations(scans[1].id).unwrap()[0];
    assert_eq!(*usage1, pq_core::evidence::Usage::Collected);
    for (_obs, usage) in store.scan_observations(scans[0].id).unwrap() {
        assert_eq!(
            usage,
            pq_core::evidence::Usage::Cached,
            "second run served everything from cache"
        );
    }
}

#[test]
fn probe_uses_the_recorded_observation_shape() {
    // The TLS report data comes from the one observation definition.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(pq_core::evidence::Store::open(dir.path()).unwrap());
    let evidence = Evidence::with_transports(
        store.clone(),
        serde_json::json!({}),
        Arc::new(CountingHttp::default()),
        Arc::new(CountingDns::default()),
        Arc::new(CountingTls::default()),
    );
    let context = ScanContext::unlimited(evidence);
    let report = check_domain("example.com", &context).unwrap();
    let pq_session = match report.tls {
        pq_pulse::model::TlsState::Tls(session) => session,
        other => panic!("expected TLS session, got {other:?}"),
    };
    assert!(pq_session.is_pq(), "kex group X25519MLKEM768 reads as PQ");
    assert_eq!(pq_session.facts.symmetric_alg.as_str(), "AES-128");

    // The observation provenance survived: latest TLS observation for the
    // endpoint carries the recorded facts.
    let req = pq_core::evidence::collectors::tls::TlsRequest::new("example.com", 443).unwrap();
    let history = store.observation_history(&req.key(), 1).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].metadata["kex_group"], "X25519MLKEM768");
}

#[allow(dead_code)]
fn type_witnesses(ip: IpAddr) {
    let _ = ip;
}
