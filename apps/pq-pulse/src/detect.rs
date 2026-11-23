mod asn;
mod cert;
pub mod decision;
mod dns;
mod http;
mod limits;
mod mail;
mod ranges;
mod rdap;
mod tls;

use std::sync::OnceLock;

use crate::providers::{match_cname_chain_vendor, match_vendor};

use chrono::Local;
use thiserror::Error;

use crate::evidence::Evidence as StoreEvidence;
use crate::model::{CnameEvidence, DomainReport, PtrEvidence, RangeEvidence, TlsState};

use asn::asn_lookup;
use dns::{dig_cname_chain, dig_ptr, resolve};
use http::probe_http;
use limits::{HostLocks, Limits, RateLimiter};
use mail::probe_mail_with_ranges;

use ranges::{VendorRanges, get_vendor_ranges, ip_in_ranges};
use rdap::rdap_lookup;
use tls::probe;

pub struct ScanContext {
    pub ranges: VendorRanges,
    pub(crate) limits: Option<Limits>,
    pub web_only: bool,
    /// Refine unconfirmed attributions with semantic reasoning.
    pub semantic_reasoning: bool,
    /// Reason of the first decision-model failure; all later checks fail.
    pub(crate) semantic_reasoning_failed: OnceLock<String>,
    /// Print semantic-reasoning request and response traffic.
    pub debug: bool,
    /// The shared evidence store and this run's scan: every collection below
    /// goes through it, and the scan records exactly which observations this
    /// run consumed.
    pub store_evidence: StoreEvidence,
}

impl ScanContext {
    pub fn unlimited(store_evidence: StoreEvidence) -> Self {
        Self {
            ranges: get_vendor_ranges(&store_evidence),
            limits: None,
            web_only: false,
            semantic_reasoning: false,
            semantic_reasoning_failed: OnceLock::new(),
            debug: false,
            store_evidence,
        }
    }

    pub fn polite(store_evidence: StoreEvidence) -> Self {
        Self {
            ranges: get_vendor_ranges(&store_evidence),
            limits: Some(Limits {
                limiter: RateLimiter::new(),
                host_locks: HostLocks::new(),
            }),
            web_only: false,
            semantic_reasoning: false,
            semantic_reasoning_failed: OnceLock::new(),
            debug: false,
            store_evidence,
        }
    }
}

/// Detection failures; `Display` forwards the upstream message unchanged.
#[derive(Debug, Error)]
pub enum DetectError {
    #[error("decision model: {0}")]
    DecisionModel(String),
    #[error("evidence store: {0}")]
    Evidence(#[from] pq_core::evidence::Error),
    #[error("tls connect: {0}")]
    TlsConnect(#[from] pq_core::evidence::collectors::tls_connector::TlsConnectError),
    #[error("{0}")]
    InvalidServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("{0}")]
    Tls(#[from] rustls::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub fn check_domain(host: &str, context: &ScanContext) -> Result<DomainReport, DetectError> {
    let evidence = &context.store_evidence;
    let resolved_ip = resolve(evidence, host);

    let cname_chain = dig_cname_chain(evidence, host);
    let cname = (!cname_chain.is_empty()).then(|| CnameEvidence {
        vendor: match_cname_chain_vendor(&cname_chain),
        chain: cname_chain,
    });

    let range = resolved_ip
        .as_ref()
        .and_then(|ip| ip_in_ranges(ip, &context.ranges))
        .map(|(vendor, cidr)| RangeEvidence { cidr, vendor });

    let (tls, cert, http, page, email, ptr, rdap, asn) = std::thread::scope(|scope| {
        let mail = (!context.web_only).then(|| {
            let evidence = evidence.clone();
            scope.spawn(move || {
                probe_mail_with_ranges(&evidence, host, &context.ranges, context.limits.as_ref())
            })
        });

        let (tls, cert_der) = match probe(evidence, host) {
            Ok((facts, cert)) => (TlsState::Tls(facts), cert),
            Err(_) => (TlsState::Unavailable, None),
        };

        let cert = cert_der.as_deref().and_then(cert::parse_cert_evidence);

        let (http, page) = probe_http(evidence, host);

        let ptr = resolved_ip
            .and_then(|ip| dig_ptr(evidence, &ip.to_string()))
            .map(|record| PtrEvidence {
                vendor: match_vendor(&record),
                record,
            });

        let rdap = resolved_ip
            .map(|ip| ip.to_string())
            .as_deref()
            .and_then(|ip| rdap_lookup(evidence, ip));

        let asn = resolved_ip.and_then(|ip| asn_lookup(evidence, ip));

        let email = match mail {
            Some(handle) => handle.join().unwrap_or_default(),
            None => None,
        };

        (tls, cert, http, page, email, ptr, rdap, asn)
    });

    let mut report = DomainReport::build(
        host.to_string(),
        resolved_ip,
        tls,
        crate::model::Evidence {
            cname,
            range,
            cert,
            http,
            ptr,
            rdap,
            asn,
        },
        email,
        Local::now(),
    );
    report.page = page;
    decision::refine(&mut report, context).map_err(DetectError::DecisionModel)?;
    Ok(report)
}
