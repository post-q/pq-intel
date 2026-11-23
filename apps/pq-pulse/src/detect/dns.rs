//! DNS collection through the shared evidence store.
//!
//! Every lookup is a store-backed DNS-kind observation (`DnsRequest` over
//! the `DnsCollector`): resolver identity is part of the collection key,
//! RRsets are preserved, positive and negative answers are cached under
//! their own policies, and TTLs drive freshness with stale reuse permitted.
//! The `dig` shell-out this module used to carry is gone; the DoH fallback
//! is a distinct resolver identity (`ResolverId::DoH`), not an HTTP probe.

use std::net::{IpAddr, ToSocketAddrs};

use pq_core::evidence::collectors::dns::{DnsAnswer, DnsRecordType, ResolverId};
use pq_core::evidence::freshness::FreshnessRequirement;

use crate::evidence::Evidence;
use crate::model::MxRecord;

/// Caller-side staleness bound for this path (matches the default policy window).
const POLICY_BOUND_SECS: u64 = 3600;

/// CNAME chains longer than this are cut off (loop guard).
pub(crate) const MAX_CNAME_HOPS: usize = 8;

/// Collect one DNS observation through the store; the decoded answer on any
/// usable outcome (positive or valid negative), `None` when the collection
/// failed and nothing usable is stored.
fn collect_dns(
    evidence: &Evidence,
    name: &str,
    rtype: DnsRecordType,
    resolver: ResolverId,
) -> Option<DnsAnswer> {
    let req = pq_core::evidence::collectors::dns::DnsRequest::new(name, rtype, resolver).ok()?;
    let outcome = evidence
        .scan
        .collect(
            &evidence.dns,
            req,
            FreshnessRequirement::MaxAge(std::time::Duration::from_secs(POLICY_BOUND_SECS)),
        )
        .ok()?;
    outcome.data
}

pub(crate) fn resolve(evidence: &Evidence, host: &str) -> Option<IpAddr> {
    resolve_all(evidence, host).into_iter().next()
}

pub(crate) fn resolve_all(evidence: &Evidence, host: &str) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for rtype in [DnsRecordType::A, DnsRecordType::AAAA] {
        let Some(answer) = collect_dns(evidence, host, rtype, ResolverId::System) else {
            continue;
        };
        for ip in answer.a_records().into_iter().chain(answer.aaaa_records()) {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
    }
    // The store answered for neither family: local resolution is the last
    // resort (getaddrinfo follows search domains the collector cannot see).
    if addresses.is_empty() {
        addresses = fallback_resolve(host);
    }
    addresses
}

fn fallback_resolve(host: &str) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    if let Ok(addrs) = (host, 443u16).to_socket_addrs() {
        for addr in addrs {
            if !addresses.contains(&addr.ip()) {
                addresses.push(addr.ip());
            }
        }
    }
    addresses
}

pub(crate) fn dig_mx(evidence: &Evidence, domain: &str) -> Vec<MxRecord> {
    let Some(answer) = collect_dns(evidence, domain, DnsRecordType::MX, ResolverId::System) else {
        return Vec::new();
    };
    let mut records: Vec<MxRecord> = answer
        .mx_records()
        .into_iter()
        .map(|(priority, host)| MxRecord { priority, host })
        .collect();
    records.sort_by_key(|record| record.priority);
    records
}

pub(crate) fn dig_cname(evidence: &Evidence, domain: &str) -> Option<String> {
    let answer = collect_dns(evidence, domain, DnsRecordType::CNAME, ResolverId::System)?;
    answer.cname().map(|c| c.trim_end_matches('.').to_string())
}

/// The complete CNAME chain, following every hop until a name has no
/// CNAME, instead of inspecting only the first hop.
pub(crate) fn dig_cname_chain(evidence: &Evidence, domain: &str) -> Vec<String> {
    follow_cname_chain(domain, |name| dig_cname(evidence, name), MAX_CNAME_HOPS)
}

fn follow_cname_chain<F>(domain: &str, lookup: F, max_hops: usize) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    let mut chain = Vec::new();
    let mut current = domain.to_string();
    for _ in 0..max_hops {
        let Some(next) = lookup(&current) else { break };
        if next == domain || chain.contains(&next) {
            break;
        }
        current = next.clone();
        chain.push(next);
    }
    chain
}

pub(crate) fn dig_ptr(evidence: &Evidence, ip: &str) -> Option<String> {
    let parsed: IpAddr = ip.parse().ok()?;
    let name = pq_core::net::reverse_name(parsed);
    let answer = collect_dns(evidence, &name, DnsRecordType::PTR, ResolverId::System)?;
    answer.ptr().map(|p| p.trim_end_matches('.').to_string())
}

/// First TXT record of a name, without the surrounding quotes. The local
/// resolver answers first; a failed or unusable answer falls back to the
/// DoH resolver — a different source identity, so both observations are
/// kept and neither contradicts the other.
pub(crate) fn dig_txt(evidence: &Evidence, name: &str) -> Option<String> {
    let local = collect_dns(evidence, name, DnsRecordType::TXT, ResolverId::System);
    let local_txt = local
        .as_ref()
        .and_then(|a| a.txt_strings().into_iter().next());
    if let Some(record) = local_txt {
        return Some(record.trim_matches('"').to_string());
    }
    // Local resolver had nothing usable (timeout, SERVFAIL, or empty):
    // some VPS resolvers SERVFAIL third-party zones and block external
    // UDP/53, while HTTPS egress keeps working.
    let via_doh = collect_dns(evidence, name, DnsRecordType::TXT, Evidence::doh_resolver());
    via_doh
        .and_then(|a| a.txt_strings().into_iter().next())
        .map(|record| record.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::MX;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    /// MX answers come back priority-sorted, regardless of wire order.
    #[test]
    fn mx_records_are_priority_sorted() {
        use crate::evidence::Evidence;
        use pq_core::evidence::collectors::dns_transport::testing::CannedDnsTransport;
        use std::sync::Arc;

        let mut answer = Message::new();
        answer.set_response_code(ResponseCode::NoError);
        let name = Name::from_utf8("example.com.").unwrap();
        answer.add_query(Query::query(name.clone(), RecordType::MX));
        answer.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::MX(MX::new(20, Name::from_utf8("mx2.example.com.").unwrap())),
        ));
        answer.add_answer(Record::from_rdata(
            name,
            300,
            RData::MX(MX::new(10, Name::from_utf8("mx1.example.com.").unwrap())),
        ));

        let transport = Arc::new(CannedDnsTransport::new(vec![(
            ("example.com".into(), RecordType::MX.into()),
            answer,
        )]));
        let dir = tempfile::tempdir().unwrap();
        let store = pq_core::evidence::Store::open(dir.path()).unwrap();
        let evidence = Evidence::with_transports(
            Arc::new(store),
            serde_json::json!({}),
            Arc::new(crate::evidence::testing::FailingHttpExecutor),
            transport,
            Arc::new(crate::evidence::testing::FailingTlsConnector),
        );

        let records = dig_mx(&evidence, "example.com");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].priority, 10);
        assert_eq!(records[0].host, "mx1.example.com");
        assert_eq!(records[1].priority, 20);
        assert_eq!(records[1].host, "mx2.example.com");
    }

    #[test]
    fn chain_follows_every_hop_to_the_end() {
        let lookup = |name: &str| match name {
            "www.example.com" => Some("www.example.com.glb.example.org".to_string()),
            "www.example.com.glb.example.org" => Some("www.example.com.edgekey.net".to_string()),
            "www.example.com.edgekey.net" => Some("e970.dspg.akamaiedge.net".to_string()),
            _ => None,
        };
        let chain = follow_cname_chain("www.example.com", lookup, MAX_CNAME_HOPS);
        assert_eq!(
            chain,
            vec![
                "www.example.com.glb.example.org".to_string(),
                "www.example.com.edgekey.net".to_string(),
                "e970.dspg.akamaiedge.net".to_string(),
            ]
        );
    }

    #[test]
    fn chain_stops_on_loops() {
        let back_and_forth = |name: &str| match name {
            "a.example.com" => Some("b.example.com".to_string()),
            "b.example.com" => Some("a.example.com".to_string()),
            _ => None,
        };
        assert_eq!(
            follow_cname_chain("a.example.com", back_and_forth, MAX_CNAME_HOPS),
            vec!["b.example.com".to_string()]
        );
    }
}
