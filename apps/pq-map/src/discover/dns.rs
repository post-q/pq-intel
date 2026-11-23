use hickory_proto::rr::RecordType;

use crate::model::{HttpsRecord, MxRecord, SrvRecord};
use crate::store::MapEvidence;

use pq_core::evidence::FreshnessRequirement;
use pq_core::evidence::collectors::dns::{
    DnsAnswer, DnsCollector, DnsRecordView, DnsRequest, ResolverId,
};

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

#[derive(Debug, Default)]
pub struct DnsDiscovery {
    pub srv: Vec<SrvRecord>,
    pub https: Vec<HttpsRecord>,
    pub mx: Vec<MxRecord>,
}

pub fn service_label(service: &str) -> &str {
    SRV_SERVICES
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, label)| *label)
        .unwrap_or(service)
}

/// SRV sweep over the well-known service prefixes plus SVCB/HTTPS on the apex.
/// Individual query failures are logged, never fatal (parity with dig-based sweep).
/// Queries are store-backed DNS collections; the blocking collects run off
/// the async runtime.
pub async fn discover(domain: &str, ev: &MapEvidence) -> DnsDiscovery {
    let domain = domain.to_string();
    let ev = ev.clone();
    tokio::task::spawn_blocking(move || discover_blocking(&domain, &ev))
        .await
        .unwrap_or_default()
}

fn discover_blocking(domain: &str, ev: &MapEvidence) -> DnsDiscovery {
    let mut out = DnsDiscovery::default();

    for (service, _) in SRV_SERVICES {
        let fqdn = format!("{service}.{domain}");
        let Some(answer) = query(ev, &fqdn, RecordType::SRV) else {
            continue;
        };
        for (priority, weight, port, target) in answer.srv_records() {
            out.srv.push(SrvRecord {
                service: service.to_string(),
                fqdn: fqdn.clone(),
                priority: u32::from(priority),
                weight: u32::from(weight),
                port,
                target,
            });
        }
    }
    out.srv
        .sort_by(|a, b| (&a.fqdn, a.priority).cmp(&(&b.fqdn, b.priority)));

    for rr in [RecordType::SVCB, RecordType::HTTPS] {
        let rr_name = rr_name(rr);
        let Some(answer) = query(ev, domain, rr) else {
            continue;
        };
        for view in &answer.records {
            if let Some(rec) = rr_from_view(rr_name, view) {
                out.https.push(rec);
            }
        }
    }

    if let Some(answer) = query(ev, domain, RecordType::MX) {
        for (priority, target) in answer.mx_records() {
            out.mx.push(MxRecord {
                priority: u32::from(priority),
                target,
            });
        }
    }
    out.mx.sort_by_key(|a| (a.priority, a.target.clone()));

    out
}

fn rr_name(rr: RecordType) -> &'static str {
    match rr {
        RecordType::SVCB => "SVCB",
        RecordType::HTTPS => "HTTPS",
        _ => "SVCB",
    }
}

/// One store-backed DNS query. Returns the decoded answer, or None when
/// the collection failed (failures are recorded in the store; callers log
/// and move on — parity with the dig-era sweep). TTLs drive freshness in
/// the store; `DNS_STALE_SECS` bounds how stale a reused answer may be.
pub(crate) fn query(ev: &MapEvidence, name: &str, rr: RecordType) -> Option<DnsAnswer> {
    let req = DnsRequest::new(name, rr, ResolverId::System).ok()?;
    let collector = DnsCollector::new(ev.dns.clone());
    match ev.scan.collect(
        &collector,
        req,
        FreshnessRequirement::MaxAge(std::time::Duration::from_secs(DNS_STALE_SECS)),
    ) {
        Ok(outcome) => {
            if let Some(f) = &outcome.failure {
                eprintln!("DNS: {} {} query failed: {:?}", rr_name(rr), name, f.status);
            }
            outcome.data
        }
        Err(e) => {
            eprintln!("DNS: {} {} query failed: {e}", rr_name(rr), name);
            None
        }
    }
}

/// How stale a reused DNS answer may be before a re-collection (seconds).
const DNS_STALE_SECS: u64 = 3600;

pub fn strip_dot(target: &str) -> String {
    if target == "." {
        ".".to_string()
    } else {
        target.trim_end_matches('.').to_lowercase()
    }
}

pub fn srv_from_view(service: &str, fqdn: &str, view: &DnsRecordView) -> Option<SrvRecord> {
    let (priority, weight, port, target) =
        pq_core::evidence::collectors::dns::parse_srv_presentation(&view.rdata)?;
    Some(SrvRecord {
        service: service.to_string(),
        fqdn: fqdn.to_string(),
        priority: u32::from(priority),
        weight: u32::from(weight),
        port,
        target,
    })
}

pub fn mx_from_view(view: &DnsRecordView) -> Option<MxRecord> {
    let (priority, target) =
        pq_core::evidence::collectors::dns::parse_mx_presentation(&view.rdata)?;
    Some(MxRecord {
        priority: u32::from(priority),
        target,
    })
}

/// SVCB/HTTPS rdata arrives as hickory's presentation string
/// (`"1 dot.example.com. alpn="h2" ipv4hint=1.2.3.4"`); the first two
/// tokens are priority and target, the rest are params.
pub fn rr_from_view(rr_type: &str, view: &DnsRecordView) -> Option<HttpsRecord> {
    let mut parts = view.rdata.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let target = strip_dot(parts.next()?);
    let params = parts.collect::<Vec<_>>().join(" ");
    Some(HttpsRecord {
        rr_type: rr_type.to_string(),
        priority,
        target,
        params,
    })
}

pub fn in_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn alpn_param(params: &str) -> Option<String> {
    params
        .split_whitespace()
        .find_map(|token| token.strip_prefix("alpn="))
        .map(|v| v.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::time::Duration;

    #[test]
    fn strip_dot_variants() {
        assert_eq!(strip_dot("sip.example.com."), "sip.example.com");
        assert_eq!(strip_dot("."), ".");
        assert_eq!(strip_dot("CDN.Example.COM."), "cdn.example.com");
    }

    #[test]
    fn in_domain_boundaries() {
        assert!(in_domain("example.com", "example.com"));
        assert!(in_domain("www.example.com", "example.com"));
        assert!(in_domain("a.b.example.com", "example.com"));
        assert!(!in_domain("notexample.com", "example.com"));
        assert!(!in_domain("example.com.evil.com", "example.com"));
        assert!(!in_domain("other.pl", "example.com"));
    }

    #[test]
    fn alpn_param_extraction() {
        assert_eq!(alpn_param("alpn=h2,h3").as_deref(), Some("h2,h3"));
        assert_eq!(
            alpn_param("ipv4hint=1.2.3.4 alpn=\"h2,http/1.1\"").as_deref(),
            Some("h2,http/1.1")
        );
        assert_eq!(alpn_param("ipv4hint=1.2.3.4"), None);
        assert_eq!(alpn_param(""), None);
    }

    #[test]
    fn service_labels_cover_table() {
        assert_eq!(service_label("_sip._tls"), "SIP/TLS");
        assert_eq!(service_label("_matrix-fed._tcp"), "Matrix federation");
        assert_eq!(service_label("_unknown._tcp"), "_unknown._tcp");
    }

    #[test]
    fn timeout_is_bounded() {
        let cfg = Config::from_env();
        assert!(cfg.dns_timeout <= Duration::from_secs(30));
    }
}
