//! Tier-2 collector tests: real collectors over canned transports — DNS TTL
//! semantics, negative caching, stale permission; HTTP conditional
//! revalidation (ETag/304).

mod common;

use common::*;
use hickory_proto::op::{Message, Query as DnsQuery, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use pq_core::evidence::collectors::dns::{DnsCollector, DnsRequest, ResolverId};
use pq_core::evidence::collectors::dns_transport::testing::CannedDnsTransport;
use pq_core::evidence::collectors::http_collector::{HttpCollector, HttpRequest_};
use pq_core::evidence::freshness::FreshnessRequirement as F;
use pq_core::evidence::http::{HttpExecError, HttpExecutor, HttpRequest, HttpResponse};
use pq_core::evidence::key::CollectionRequest;
use pq_core::evidence::store::Usage;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn dns_answer_message(
    name: &str,
    rtype: RecordType,
    records: Vec<(RecordType, u32, RData)>,
) -> Message {
    let mut msg = Message::new();
    msg.set_response_code(ResponseCode::NoError);
    let name = Name::from_utf8(name).unwrap();
    msg.add_query(DnsQuery::query(name.clone(), rtype));
    for (_rt, ttl, data) in records {
        msg.add_answer(Record::from_rdata(name.clone(), ttl, data));
    }
    msg
}

fn nxdomain_message(name: &str, soa_ttl: u32, minimum: u32) -> Message {
    use hickory_proto::rr::rdata::SOA;
    let mut msg = Message::new();
    msg.set_response_code(ResponseCode::NXDomain);
    let name = Name::from_utf8(name).unwrap();
    msg.add_query(DnsQuery::query(name.clone(), RecordType::A));
    let soa = SOA::new(
        Name::from_utf8("ns1.example.com.").unwrap(),
        Name::from_utf8("hostmaster.example.com.").unwrap(),
        1,       // serial
        3600,    // refresh
        900,     // retry
        1800,    // expire
        minimum, // minimum (negative TTL)
    );
    msg.add_name_server(Record::from_rdata(name, soa_ttl, RData::SOA(soa)));
    msg
}

fn canned_dns(responses: Vec<Message>) -> (Arc<CannedDnsTransport>, DnsCollector) {
    // Keyed by (name, type); single-question tests.
    let mut keyed = Vec::new();
    for m in responses {
        let q = m.queries().first().unwrap();
        keyed.push((
            (
                q.name()
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                q.query_type().into(),
            ),
            m,
        ));
    }
    let transport = Arc::new(CannedDnsTransport::new(keyed));
    let collector = DnsCollector::new(transport.clone());
    (transport, collector)
}

#[test]
fn dns_positive_answer_respects_ttl_clamps() {
    let (_dir, store) = open_store();
    // TTL-driven (default dns/default policy): clamp [30s, 86400s], stale ok.
    let answer = dns_answer_message(
        "example.com",
        RecordType::A,
        vec![(RecordType::A, 5, RData::A(A::new(93, 184, 216, 34)))],
    );
    let (transport, collector) = canned_dns(vec![answer]);
    let req = DnsRequest::new(
        "example.com",
        RecordType::A,
        ResolverId::Udp("1.1.1.1:53".into()),
    )
    .unwrap();

    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();

    assert_eq!(out.usage, Usage::Collected);
    assert_eq!(out.data_status, pq_core::evidence::DataStatus::Fresh);
    let obs = out.observation.unwrap();
    // TTL 5s clamped up to ttl_min 30s.
    assert_eq!(obs.fresh_until, Some(obs.observed_at + 30));
    let decoded = out.data.unwrap();
    assert_eq!(
        decoded.a_records(),
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(transport.call_count(), 1);

    // Second read: fresh (within clamp) → cached, no new query.
    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(out.usage, Usage::Cached);
    assert_eq!(transport.call_count(), 1);
}

#[test]
fn dns_negative_answer_cached_under_negative_policy() {
    let (_dir, store) = open_store();
    let answer = nxdomain_message("missing.example.com", 7200, 1800);
    let (transport, collector) = canned_dns(vec![answer]);
    let req = DnsRequest::new(
        "missing.example.com",
        RecordType::A,
        ResolverId::Udp("1.1.1.1:53".into()),
    )
    .unwrap();

    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();

    // NXDOMAIN is a valid negative answer — knowledge, not failure.
    assert_eq!(
        out.observation.as_ref().unwrap().status,
        pq_core::evidence::ObservationStatus::NotFound
    );
    // Native status preserved verbatim (hickory's rcode display).
    assert_eq!(
        out.observation.as_ref().unwrap().native_status.as_deref(),
        Some("dns:Non-Existent Domain")
    );
    let obs = out.observation.unwrap();
    // negative TTL = min(SOA TTL 7200, SOA MINIMUM 1800) = 1800, within
    // negative policy clamp [60, 10800] → 1800.
    assert_eq!(obs.fresh_until, Some(obs.observed_at + 1800));

    // Re-read: the negative answer is served from cache (no repeat query).
    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(out.usage, Usage::Cached);
    assert_eq!(transport.call_count(), 1);
}

#[test]
fn different_resolvers_are_different_collections() {
    let (_dir, store) = open_store();
    let answer = dns_answer_message(
        "example.com",
        RecordType::A,
        vec![(RecordType::A, 300, RData::A(A::new(1, 2, 3, 4)))],
    );
    let (transport, collector) = canned_dns(vec![answer.clone(), answer]);
    let via_one = DnsRequest::new(
        "example.com",
        RecordType::A,
        ResolverId::Udp("1.1.1.1:53".into()),
    )
    .unwrap();
    let via_system = DnsRequest::new("example.com", RecordType::A, ResolverId::System).unwrap();

    let scan = store.begin_scan("test", json!({})).unwrap();
    scan.collect(
        &collector,
        via_one.clone(),
        F::MaxAge(std::time::Duration::from_secs(3600)),
    )
    .unwrap();
    let second = scan
        .collect(
            &collector,
            via_system,
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    // Different resolver → different collection → fresh collection, not cache.
    assert_eq!(second.usage, Usage::Collected);
    assert_eq!(transport.call_count(), 2);

    // And the first resolver's read is still cached.
    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            via_one,
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(out.usage, Usage::Cached);
}

// --- HTTP conditional revalidation ------------------------------------------

struct CannedHttpExecutor {
    responses: Mutex<Vec<HttpResponse>>,
    pub requests: Mutex<Vec<HttpRequest>>,
}

impl CannedHttpExecutor {
    fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses),
            requests: Mutex::new(vec![]),
        })
    }
}

impl HttpExecutor for CannedHttpExecutor {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpExecError> {
        self.requests.lock().unwrap().push(req.clone());
        Ok(self.responses.lock().unwrap().remove(0))
    }
}

fn http_response(status: u16, headers: Vec<(&str, &str)>, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.as_bytes().to_vec(),
        final_url: "https://example.com/".into(),
        redirect_chain: vec![],
    }
}

#[test]
fn http_304_confirms_cached_body_without_duplicate_artifact() {
    let (_dir, store) = open_store();
    // Expire the http policy up front so the second read must revalidate.
    store
        .set_policy(&pq_core::evidence::Policy {
            kind: "http".into(),
            name: "default".into(),
            fresh_for: Some(Duration::ZERO),
            allow_stale: false,
            stale_for: None,
            ttl_min: None,
            ttl_max: None,
        })
        .unwrap();
    let executor = CannedHttpExecutor::new(vec![
        http_response(
            200,
            vec![("etag", "\"v1\""), ("content-type", "text/html")],
            "<html>v1</html>",
        ),
        http_response(304, vec![("etag", "\"v1\"")], ""),
    ]);
    let collector = HttpCollector {
        http: executor.clone(),
    };
    let req = HttpRequest_::get("https://example.com/").unwrap();

    // First: fresh 200 with body.
    let scan = store.begin_scan("test", json!({})).unwrap();
    let first = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(first.usage, Usage::Collected);
    let body1 = first
        .observation
        .as_ref()
        .unwrap()
        .artifact_by_role("response_body")
        .unwrap()
        .hash;

    // Second: 304 confirms the representation.
    let scan = store.begin_scan("test", json!({})).unwrap();
    let second = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();

    assert_eq!(second.usage, Usage::Refreshed);
    assert_eq!(second.data_status, pq_core::evidence::DataStatus::Fresh);
    // The conditional request carried the validator.
    let second_request = &executor.requests.lock().unwrap()[1];
    assert!(
        second_request
            .headers
            .iter()
            .any(|(k, v)| k == "if-none-match" && v == "\"v1\"")
    );
    // Same body artifact — no duplicate download artifact.
    let body2 = second
        .observation
        .as_ref()
        .unwrap()
        .artifact_by_role("response_body")
        .unwrap()
        .hash;
    assert_eq!(
        body1, body2,
        "304 re-links the cached body, no duplicate artifact"
    );
    // Both observations exist in history; the new one is the fresh read.
    assert_eq!(store.observation_history(&req.key(), 10).unwrap().len(), 2);
}

#[test]
fn http_404_is_cached_negative() {
    let (_dir, store) = open_store();
    let executor = CannedHttpExecutor::new(vec![http_response(404, vec![], "not found")]);
    let collector = HttpCollector {
        http: executor.clone(),
    };
    let req = HttpRequest_::get("https://example.com/nope").unwrap();
    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req.clone(),
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(
        out.observation.as_ref().unwrap().status,
        pq_core::evidence::ObservationStatus::NotFound
    );
    assert_eq!(
        out.observation.as_ref().unwrap().native_status.as_deref(),
        Some("404")
    );

    // Cached negative: second read does not re-request.
    let scan = store.begin_scan("test", json!({})).unwrap();
    let out = scan
        .collect(
            &collector,
            req,
            F::MaxAge(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    scan.finish().unwrap();
    assert_eq!(out.usage, Usage::Cached);
    assert_eq!(executor.requests.lock().unwrap().len(), 1);
}
