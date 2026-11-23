use std::net::IpAddr;

use crate::model::DnsStatus;
use crate::store::MapEvidence;

/// Resolve a hostname (A/AAAA) and classify the DNS response status.
/// Both families are store-backed DNS collections (see `dns::query`);
/// the old tokio resolver is gone.
pub fn resolve_status(ev: &MapEvidence, host: &str) -> (Option<IpAddr>, DnsStatus) {
    let a = super::dns::query(ev, host, hickory_proto::rr::RecordType::A);
    let aaaa = super::dns::query(ev, host, hickory_proto::rr::RecordType::AAAA);

    let ip = a
        .as_ref()
        .and_then(|ans| ans.a_records().into_iter().next())
        .or_else(|| {
            aaaa.as_ref()
                .and_then(|ans| ans.a_records().into_iter().next())
        });

    // Status classification follows the A answer when present, else AAAA.
    let status = match (&a, &aaaa) {
        (Some(ans), _) | (None, Some(ans)) => status_of(ans),
        (None, None) => DnsStatus::Timeout,
    };
    (ip, status)
}

/// Wire rcode → pq-map's DnsStatus.
fn status_of(ans: &pq_core::evidence::collectors::dns::DnsAnswer) -> DnsStatus {
    match ans.rcode.to_ascii_uppercase().as_str() {
        "NXDOMAIN" => DnsStatus::NxDomain,
        "SERVFAIL" => DnsStatus::ServFail,
        "REFUSED" => DnsStatus::Refused,
        "NOERROR" if ans.negative => DnsStatus::NoData,
        "NOERROR" => DnsStatus::Ok,
        _ => DnsStatus::Other,
    }
}

/// Resolve a hostname to its first address (A, then AAAA).
pub fn resolve_first(ev: &MapEvidence, host: &str) -> Option<IpAddr> {
    resolve_status(ev, host).0
}
