//! TLS probing through the shared evidence store.
//!
//! The TLS observation has ONE definition (pq-core's `TlsCollector` +
//! `session_to_observation`): the endpoint collector serves the standard
//! connect-handshake path, cached by the `tls` policy. The SMTP STARTTLS
//! path performs its handshake on an existing socket (via the connector's
//! `upgrade`) and records the same observation shape through `Scan::record`
//! — one definition, two connection paths. This module's former hand-rolled
//! rustls probe is gone.

use pq_core::evidence::collectors::tls::session_to_observation;
use pq_core::evidence::collectors::tls_connector::TlsUpgradedSession;
use pq_core::evidence::freshness::FreshnessRequirement;

use super::DetectError;
use crate::evidence::Evidence;
use crate::model::{SymmetricAlg, TlsFacts, TlsSession};

/// Caller-side staleness bound for this path (matches the default policy window).
const POLICY_BOUND_SECS: u64 = 86400;

/// Handshake timeout for the SMTP upgrade path (the endpoint collector
/// carries its own).
const TLS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Endpoint TLS observation (443): store-backed, so an unchanged endpoint
/// inside the freshness window costs zero network I/O.
pub(crate) fn probe(
    evidence: &Evidence,
    host: &str,
) -> Result<(TlsSession, Option<Vec<u8>>), DetectError> {
    let req = pq_core::evidence::collectors::tls::TlsRequest::new(host, 443)
        .map_err(DetectError::from)?;
    let outcome = evidence
        .scan
        .collect(
            &evidence.tls,
            req,
            FreshnessRequirement::MaxAge(std::time::Duration::from_secs(POLICY_BOUND_SECS)),
        )
        .map_err(DetectError::from)?;
    let observation = outcome.data.ok_or_else(|| {
        DetectError::Evidence(pq_core::evidence::Error::Misuse(format!(
            "no TLS observation stored for {host}"
        )))
    })?;
    Ok(tls_session_from_observation(&observation))
}

/// Map the shared observation onto the report model.
pub(crate) fn tls_session_from_observation(
    observation: &pq_core::evidence::collectors::tls::TlsObservation,
) -> (TlsSession, Option<Vec<u8>>) {
    let session = &observation.session;
    let leaf = session.chain.first().cloned();
    (
        TlsSession {
            version: session.protocol_version.clone(),
            facts: TlsFacts {
                kx_group: session.kex_group.clone(),
                symmetric_alg: SymmetricAlg::from_suite_name(&session.cipher_suite),
            },
        },
        leaf,
    )
}

/// TLS upgrade of an existing SMTP socket: the handshake happens on the
/// live connection (the session continues over it), and the same
/// observation definition records what was negotiated.
pub(crate) fn upgrade(
    evidence: &Evidence,
    sock: std::net::TcpStream,
    host: &str,
    port: u16,
) -> Result<(TlsSession, Option<Vec<u8>>, TlsUpgradedSession), DetectError> {
    let connector = pq_core::evidence::collectors::tls_connector::RustlsConnector::new(TLS_TIMEOUT);
    let upgraded = connector
        .upgrade(host, &[], sock)
        .map_err(DetectError::from)?;
    let facts = &upgraded.facts;
    let leaf_der = facts.chain.first().cloned();

    // Record the handshake as the one TLS observation shape.
    let req = pq_core::evidence::collectors::tls::TlsRequest::new(host, port)
        .map_err(DetectError::from)?;
    let _ = evidence
        .scan
        .record(&req, session_to_observation(host, port, facts))
        .map_err(DetectError::from)?;

    let session = TlsSession {
        version: facts.protocol_version.clone(),
        facts: TlsFacts {
            kx_group: facts.kex_group.clone(),
            symmetric_alg: SymmetricAlg::from_suite_name(&facts.cipher_suite),
        },
    };
    Ok((session, leaf_der, upgraded))
}
