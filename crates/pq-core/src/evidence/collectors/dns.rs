//! The DNS collector: hickory-wire-format DNS over pluggable transports.
//!
//! Resolver identity is part of the collection key — different resolvers'
//! answers are observations of different collections, never contradictions.
//! Complete RRsets are preserved in the observation metadata. Negative
//! answers (NXDOMAIN, NODATA) are cached under the `negative` policy with
//! their own TTL math (RFC 2308: min(SOA TTL, SOA MINIMUM)).
//!
//! This collector replaces `pq-pulse`'s `dig` shell-out: the CLI's record
//! types (A, AAAA, MX, CNAME, PTR, TXT) map onto [`DnsRequest`]s, and its
//! DoH fallback becomes [`ResolverId::DoH`] — a DNS-kind observation using
//! HTTP as transport, not an HTTP observation.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::{Error, Result};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{ObservationStatus, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use crate::net::normalize_domain;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// DNS wire-format re-export: consumers name DNS record types through
/// pq-core without touching hickory directly.
pub use hickory_proto::rr::RecordType as DnsRecordType;

/// Which resolver answers this collection: part of the identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResolverId {
    /// System-configured default resolution (recursion via resolv.conf).
    System,
    /// Direct UDP query to the resolver at this address (IP:port).
    Udp(String),
    /// Direct TCP query to the resolver at this address (IP:port).
    Tcp(String),
    /// DNS over HTTPS at this endpoint URL — same DNS-kind observation,
    /// distinct source identity.
    DoH(String),
}

impl ResolverId {
    pub fn identity(&self) -> String {
        match self {
            ResolverId::System => "system".to_string(),
            ResolverId::Udp(addr) => format!("udp:{addr}"),
            ResolverId::Tcp(addr) => format!("tcp:{addr}"),
            ResolverId::DoH(url) => format!("doh:{url}"),
        }
    }
}

/// A DNS question: name, type, class, resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRequest {
    /// Normalized query name (ASCII lowercase, no trailing dot, no wildcard).
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub resolver: ResolverId,
}

impl DnsRequest {
    pub fn new(name: &str, rtype: RecordType, resolver: ResolverId) -> Result<Self> {
        let name = normalize_domain(name)
            .ok_or_else(|| Error::Misuse(format!("invalid DNS name `{name}`")))?;
        Ok(Self {
            name,
            rtype: rtype.into(),
            rclass: DNSClass::IN.into(),
            resolver,
        })
    }
}

impl CollectionRequest for DnsRequest {
    const KIND: &'static str = "dns";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("name", &self.name);
        w.u16_field("rtype", self.rtype);
        w.u16_field("rclass", self.rclass);
        w.str_field("resolver", &self.resolver.identity());
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "rtype": self.rtype,
            "rclass": self.rclass,
            "resolver": self.resolver.identity(),
        })
    }
}

/// One preserved record of an RRset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecordView {
    pub name: String,
    pub rtype: String,
    pub class: String,
    pub ttl: u32,
    /// Presentation-format rdata (e.g. `93.184.216.34`, `10 mail.example.com.`).
    pub rdata: String,
}

/// Decoded DNS observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub rcode: String,
    pub records: Vec<DnsRecordView>,
    /// True for NXDOMAIN / NODATA — a valid negative answer.
    pub negative: bool,
    /// Negative TTL (RFC 2308) when negative.
    pub negative_ttl: Option<u32>,
}

impl DnsAnswer {
    pub fn a_records(&self) -> Vec<IpAddr> {
        self.records
            .iter()
            .filter(|r| r.rtype == "A")
            .filter_map(|r| r.rdata.parse().ok())
            .collect()
    }

    pub fn aaaa_records(&self) -> Vec<IpAddr> {
        self.records
            .iter()
            .filter(|r| r.rtype == "AAAA")
            .filter_map(|r| r.rdata.parse().ok())
            .collect()
    }

    pub fn txt_strings(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|r| r.rtype == "TXT")
            .map(|r| r.rdata.clone())
            .collect()
    }

    pub fn mx_records(&self) -> Vec<(u16, String)> {
        self.records
            .iter()
            .filter(|r| r.rtype == "MX")
            .filter_map(|r| parse_mx_presentation(&r.rdata))
            .collect()
    }

    pub fn cname(&self) -> Option<String> {
        self.records
            .iter()
            .find(|r| r.rtype == "CNAME")
            .map(|r| r.rdata.clone())
    }

    pub fn ptr(&self) -> Option<String> {
        self.records
            .iter()
            .find(|r| r.rtype == "PTR")
            .map(|r| r.rdata.clone())
    }

    /// SRV records as `(priority, weight, port, target)`; target is
    /// lowercased and trailing-dot-stripped.
    pub fn srv_records(&self) -> Vec<(u16, u16, u16, String)> {
        self.records
            .iter()
            .filter(|r| r.rtype == "SRV")
            .filter_map(|r| parse_srv_presentation(&r.rdata))
            .collect()
    }
}

/// `10 mail.example.com.` → (10, "mail.example.com")
pub fn parse_mx_presentation(p: &str) -> Option<(u16, String)> {
    let mut parts = p.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let host = parts.next()?.trim_end_matches('.').to_ascii_lowercase();
    Some((priority, host))
}

/// `1 dot.example.com. alpn="h2" ipv4hint=1.2.3.4`
///   → (1, "dot.example.com", "alpn=\"h2\" ipv4hint=1.2.3.4")
///
/// SVCB/HTTPS rdata arrives as hickory's presentation string; the first
/// two tokens are priority and target, the rest are params.
pub fn parse_svcb_presentation(p: &str) -> Option<(u16, String, String)> {
    let mut parts = p.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let target = parts.next()?;
    let target = if target == "." {
        ".".to_string()
    } else {
        target.trim_end_matches('.').to_ascii_lowercase()
    };
    Some((priority, target, parts.collect::<Vec<_>>().join(" ")))
}

/// The well-known SRV service prefixes the discovery sweep covers, with
/// their display labels.
pub const SRV_SERVICES: &[(&str, &str)] = &[
    ("_ldap._tcp", "LDAP"),
    ("_ldaps._tcp", "LDAPS"),
    ("_kerberos._tcp", "Kerberos/TCP"),
    ("_kerberos._udp", "Kerberos/UDP"),
    ("_sip._tcp", "SIP/TCP"),
    ("_sip._udp", "SIP/UDP"),
    ("_sip._tls", "SIP/TLS"),
    ("_xmpp-client._tcp", "XMPP client"),
    ("_xmpp-server._tcp", "XMPP server"),
    ("_matrix-fed._tcp", "Matrix federation"),
];

/// `1 9 443 sip.example.com.` → (1, 9, 443, "sip.example.com")
pub fn parse_srv_presentation(p: &str) -> Option<(u16, u16, u16, String)> {
    let mut parts = p.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let weight: u16 = parts.next()?.parse().ok()?;
    let port: u16 = parts.next()?.parse().ok()?;
    let target = parts.next()?.trim_end_matches('.').to_ascii_lowercase();
    Some((priority, weight, port, target))
}

/// Transport error, mapped by the collector to observation statuses.
#[derive(Debug, thiserror::Error)]
pub enum DnsTransportError {
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("network: {0}")]
    Network(String),
    #[error("malformed response: {0}")]
    Malformed(String),
}

impl From<DnsTransportError> for CollectionError {
    fn from(e: DnsTransportError) -> Self {
        match e {
            DnsTransportError::Timeout(d) => CollectionError::Timeout {
                native: Some(format!("timed out after {d:?}")),
            },
            other => CollectionError::Error {
                native: None,
                message: other.to_string(),
            },
        }
    }
}

/// The network boundary for DNS: wire-format message in, wire-format message
/// out. Production: [`CompositeDnsTransport`] (UDP/TCP + DoH over the shared
/// HTTP executor). Tests: canned transports.
pub trait DnsTransport: Send + Sync {
    fn exchange(
        &self,
        resolver: &ResolverId,
        message: &Message,
    ) -> std::result::Result<Message, DnsTransportError>;
}

/// The DNS collector. Clones share the transport.
#[derive(Clone)]
pub struct DnsCollector {
    pub transport: Arc<dyn DnsTransport>,
    pub timeout: Duration,
}

impl DnsCollector {
    pub fn new(transport: Arc<dyn DnsTransport>) -> Self {
        Self {
            transport,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Collector for DnsCollector {
    type Request = DnsRequest;
    type Output = DnsAnswer;

    fn collect(
        &self,
        _scan: &Scan,
        req: &DnsRequest,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let mut query = Message::new();
        query.set_recursion_desired(true);
        let name =
            hickory_proto::rr::Name::from_utf8(&req.name).map_err(|e| CollectionError::Error {
                native: None,
                message: format!("bad name: {e}"),
            })?;
        query.add_query(hickory_proto::op::Query::query(
            name,
            RecordType::from(req.rtype),
        ));

        let response = self
            .transport
            .exchange(&req.resolver, &query)
            .map_err(CollectionError::from)?;

        let rcode = response.response_code();
        let native = format!("dns:{rcode}");
        let records: Vec<DnsRecordView> = response.answers().iter().map(record_view).collect();

        let answer = match rcode {
            ResponseCode::NoError => {
                if records.is_empty() {
                    // NODATA: valid negative answer.
                    DnsAnswer {
                        rcode: rcode.to_string(),
                        records,
                        negative: true,
                        negative_ttl: soa_negative_ttl(&response),
                    }
                } else {
                    DnsAnswer {
                        rcode: rcode.to_string(),
                        records,
                        negative: false,
                        negative_ttl: None,
                    }
                }
            }
            ResponseCode::NXDomain => DnsAnswer {
                rcode: rcode.to_string(),
                records,
                negative: true,
                negative_ttl: soa_negative_ttl(&response),
            },
            // SERVFAIL/REFUSED/FORMERR/... : the name's state is unknown, and
            // the failure is recorded without erasing any prior answer.
            other => {
                return Err(CollectionError::Error {
                    native: Some(format!("dns:{other}")),
                    message: format!("resolver returned {other}"),
                });
            }
        };

        let status = if answer.negative {
            ObservationStatus::NotFound
        } else {
            ObservationStatus::Success
        };
        let metadata = serde_json::to_value(&answer).map_err(|e| CollectionError::Error {
            native: None,
            message: format!("dns metadata: {e}"),
        })?;
        let mut raw = RawObservation::success(metadata);
        raw.status = status;
        raw.native_status = Some(native);
        if answer.negative {
            raw.fresh_hint = answer.negative_ttl.map(|t| Duration::from_secs(t as u64));
            raw.policy_name = Some("negative".into());
        } else {
            // Minimum TTL across the RRsets: no record outlives its data.
            raw.fresh_hint = answer
                .records
                .iter()
                .map(|r| Duration::from_secs(r.ttl as u64))
                .min();
        }
        Ok(raw)
    }

    fn decode(&self, _store: &Store, obs: &StoredObservation) -> Result<DnsAnswer> {
        serde_json::from_value(obs.metadata.clone()).map_err(Into::into)
    }

    fn policy_name(
        &self,
        _req: &DnsRequest,
        latest_status: Option<ObservationStatus>,
    ) -> std::borrow::Cow<'static, str> {
        if latest_status == Some(ObservationStatus::NotFound) {
            "negative".into()
        } else {
            "default".into()
        }
    }
}

/// RFC 2308 negative TTL: min(SOA record TTL, SOA MINIMUM field).
fn soa_negative_ttl(response: &Message) -> Option<u32> {
    response
        .name_servers()
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .map(|rec| {
            let minimum = rec
                .data()
                .and_then(|d| d.as_soa())
                .map(|s| s.minimum())
                .unwrap_or(rec.ttl());
            rec.ttl().min(minimum)
        })
}

fn record_view(r: &Record) -> DnsRecordView {
    let rdata = match r.data() {
        // RFC 3597 unknown rdata presentation.
        Some(hickory_proto::rr::RData::Unknown { rdata, .. }) => {
            format!(
                "\\# {} {}",
                rdata.anything().len(),
                hex_or_dump(rdata.anything())
            )
        }
        Some(data) => data.to_string(),
        None => String::new(),
    };
    DnsRecordView {
        name: r.name().to_string(),
        rtype: r.record_type().to_string(),
        class: r.dns_class().to_string(),
        ttl: r.ttl(),
        rdata,
    }
}

fn hex_or_dump(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_identity_distinguishes_sources() {
        assert_ne!(
            ResolverId::Udp("1.1.1.1:53".into()).identity(),
            ResolverId::DoH("https://cloudflare-dns.com/dns-query".into()).identity()
        );
        assert_eq!(ResolverId::System.identity(), "system");
    }

    #[test]
    fn mx_presentation_parses() {
        assert_eq!(
            parse_mx_presentation("10 mail.example.com."),
            Some((10, "mail.example.com".into()))
        );
        assert_eq!(parse_mx_presentation("not an mx"), None);
    }

    #[test]
    fn svcb_presentation_parses() {
        assert_eq!(
            parse_svcb_presentation("1 dot.example.com. alpn=\"h2\" ipv4hint=1.2.3.4"),
            Some((
                1,
                "dot.example.com".into(),
                "alpn=\"h2\" ipv4hint=1.2.3.4".into()
            ))
        );
        assert_eq!(
            parse_svcb_presentation("1 ."),
            Some((1, ".".into(), "".into()))
        );
        assert_eq!(parse_svcb_presentation(""), None);
        assert_eq!(parse_svcb_presentation("x example.com"), None);
    }

    #[test]
    fn srv_service_table_has_unique_prefixes() {
        let mut seen = std::collections::BTreeSet::new();
        for (prefix, _) in SRV_SERVICES {
            assert!(seen.insert(*prefix), "duplicate SRV prefix {prefix}");
        }
    }
}
